# What the Inspector page reads: any project on this gateway, scanned live
# through the gateway's own project manager. A saved Designer edit shows on
# the next scan; an unsaved one does not exist yet.
from java.nio.charset import StandardCharsets
from com.inductiveautomation.ignition.gateway import IgnitionGateway
from java.util.concurrent.locks import ReentrantLock
import re

_cache = {}
# Several bindings ask for the same project at once when it is picked; one
# scan serves them all instead of each starting its own.
_lock = ReentrantLock()
_MAX_AGE_MS = 5 * 60 * 1000
# The project dropdown's value for the all-projects triage.
ALL = '*'


def _manager():
	return IgnitionGateway.get().getProjectManager()


def _text(resource, key, binary=False):
	data = resource.getData(key).orElse(None)
	if data is None:
		return None
	return data.getBytesAsString(StandardCharsets.ISO_8859_1 if binary else StandardCharsets.UTF_8)


def _attrs(resource):
	out = {}
	for entry in resource.getAttributes().entrySet():
		try:
			out[entry.getKey()] = system.util.jsonDecode(str(entry.getValue()))
		except Exception:
			out[entry.getKey()] = str(entry.getValue())
	return out


def _scan_project(project):
	coll = _manager().find(project).orElse(None)
	if coll is None:
		raise ValueError('No project %s on this gateway' % project)
	views, scripts, namedQueries, background, recent, pageConfig = {}, {}, {}, [], [], {}
	for r in coll.getResources():
		rp = r.getResourcePath()
		moduleId, rtype, path = rp.getModuleId(), rp.getType(), str(rp.getFolderPath())
		attrs = _attrs(r)
		keys = list(r.getDataKeys())
		if not keys:
			continue
		change = attrs.get('lastModification') or {}
		if change.get('timestamp'):
			recent.append((change['timestamp'], change.get('actor') or '', rtype, path))
		if (moduleId, rtype) == ('com.inductiveautomation.perspective', 'views'):
			text = _text(r, 'view.json')
			if text:
				views[path] = system.util.jsonDecode(text)
		elif (moduleId, rtype) == ('ignition', 'script-python'):
			scripts[path] = _text(r, 'code.py') or ''
		elif (moduleId, rtype) == ('ignition', 'named-query'):
			namedQueries[path] = {'sql': _text(r, 'query.sql') or '', 'database': attrs.get('database') or '',
				'params': attrs.get('parameters') or []}
		elif (moduleId, rtype) == ('com.inductiveautomation.perspective', 'page-config'):
			pageConfig = system.util.jsonDecode(_text(r, 'config.json') or '{}')
		else:
			files = {}
			for key in keys:
				if key.endswith('.py') or key.endswith('.json') or key == 'data.bin':
					files[key] = _text(r, key, binary=(key == 'data.bin'))
			src = inspector.scan.background_source(moduleId, rtype, path, files, attrs)
			if src:
				background.append(src)
	inv = inspector.scan.Scanner(views, pageConfig, scripts, namedQueries, background).scan()
	manifest = coll.getManifest()
	inv['name'] = project
	inv['meta'] = {'title': manifest.title(), 'description': manifest.description(), 'parent': manifest.parent(),
		'enabled': 'yes' if manifest.enabled() else 'no'}
	inv['databases'] = [q['database'] for q in namedQueries.values()]
	recent.sort(reverse=True)
	inv['recent'] = [{'cat': 'change', 'view': '%s/%s' % (t, p), 'comp': t, 'trigger': actor, 'target': p,
		'detail': ts.replace('T', ' ').replace('Z', ' UTC')} for ts, actor, t, p in recent[:200]]
	_missing_tags(inv, project)
	inv['tree'] = _tree(inv)
	return inv


_RE_TAG_CALL = re.compile(r'system\.tag\.(read|write)')


def _missing_tags(inv, project):
	# Only paths the scan read as literals: tag and tag-history bindings, and
	# the first argument of a tag read or write. A path with no provider uses
	# the project's default provider.
	provider = _manager().getProjectProps(project).getDefaultSQLTagsProviderName() or 'default'
	known, found = {}, []
	for key, v in inv['views'].items():
		for r in v['rows']:
			if r['cat'] != 'tag' or not (r['detail'].startswith(('tag binding', 'tag history binding')) or _RE_TAG_CALL.search(r['detail'])):
				continue
			for path in (r['target'] or '').split(', '):
				path = path.strip()
				# A path ending in / is the start of one built at run time.
				if not path or path.endswith('/') or '{' in path or '(dynamic)' in path or ':/' in path or path.startswith(('[.', '[~')):
					continue
				full = path if path.startswith('[') else '[%s]%s' % (provider, path)
				if full not in known:
					known[full] = system.tag.exists(full)
				if not known[full]:
					prov = full[:full.find(']') + 1]
					if prov not in known:
						known[prov] = system.tag.exists(prov)
					why = 'no tag %s on this gateway' % full if known[prov] else 'no tag provider %s on this gateway, so no %s' % (prov, full)
					found.append((key, dict(r, cat='issue', target=path, detail=why)))
	for key, row in found:
		inv['views'][key]['rows'].append(row)


def _nest(entries):
	# entries: (segments, label, key); folders from all but the last segment.
	root = {'items': []}
	for segments, label, key in entries:
		node = root
		for seg in segments[:-1]:
			match = [n for n in node['items'] if n['label'] == seg and not n['data']]
			if not match:
				match = [{'label': seg, 'expanded': False, 'data': '', 'items': []}]
				node['items'].append(match[0])
			node = match[0]
		node['items'].append({'label': label, 'expanded': False, 'data': key, 'items': []})
	return root['items']


def _tree(inv):
	count = lambda cat: len(inspector.scan.page_rows(inv, 'report:' + cat)[0])
	checks = [{'label': 'Overview', 'expanded': False, 'data': 'report:overview', 'items': []}]
	for key, label in inspector.scan.REPORTS[1:]:
		checks.append({'label': '%s (%d)' % (label, count(key.split(':')[1])), 'expanded': False, 'data': key, 'items': []})
	items = [{'label': 'Project checks', 'expanded': True, 'data': '', 'items': checks}]
	prefix = inspector.scan.title_prefix(inv)
	entries = []
	for p in inv['pages']:
		segments = [s for s in p['route'].split('/') if s]
		label = (p['title'][len(prefix):] if p['title'] else '') or (segments[-1] if segments else 'Home')
		entries.append((segments or [''], label, 'route:' + p['route']))
	pages = _nest(entries)
	def expand(nodes):
		for n in nodes:
			if not n['data']:
				n['expanded'] = True
				expand(n['items'])
	expand(pages)
	items.append({'label': 'Pages (%d)' % len(inv['pages']), 'expanded': True, 'data': '', 'items': pages})
	if inv['sharedDocks']:
		items.append({'label': 'Shared docks', 'expanded': False, 'data': '', 'items': [
			{'label': d['id'], 'expanded': False, 'data': 'dock:' + d['id'], 'items': []} for d in inv['sharedDocks']]})
	if inv['background']:
		items.append({'label': 'Gateway scripts (%d)' % len(inv['background']), 'expanded': False, 'data': '', 'items': [
			{'label': '%s: %s' % (b['kind'], b['name']), 'expanded': False, 'data': 'view:@' + b['id'], 'items': []} for b in inv['background']]})
	if inv['unreached']:
		items.append({'label': 'Views no page reaches (%d)' % len(inv['unreached']), 'expanded': False, 'data': '', 'items': [
			{'label': v, 'expanded': False, 'data': 'view:' + v, 'items': []} for v in inv['unreached']]})
	if inv['namedQueries']:
		items.append({'label': 'Named queries (%d)' % len(inv['namedQueries']), 'expanded': False, 'data': '',
			'items': _nest([(q.split('/'), q.split('/')[-1], 'use:nq:' + q) for q in inv['namedQueries']])})
	if inv['scripts']:
		items.append({'label': 'Script library (%d)' % len(inv['scripts']), 'expanded': False, 'data': '',
			'items': _nest([(m.split('.'), m.split('.')[-1], 'use:fn:' + m) for m in inv['scripts']])})
	if inv['messages']:
		items.append({'label': 'Message types (%d)' % len(inv['messages']), 'expanded': False, 'data': '', 'items': [
			{'label': m, 'expanded': False, 'data': 'use:msg:' + m, 'items': []} for m in inv['messages']]})
	return items


def load(project, force=False):
	"""The inventory for a project, from cache when it is fresh."""
	_lock.lock()
	try:
		now = system.date.toMillis(system.date.now())
		hit = _cache.get(project)
		if hit and not force and now - hit[0] < _MAX_AGE_MS:
			return hit[1]
		try:
			inv = _scan_project(project)
		except Exception:
			# A binding transform swallows the error; the gateway log is the only place it shows.
			import traceback
			system.util.getLogger('ProjectInspector').error('Scanning %s failed:\n%s' % (project, traceback.format_exc()))
			raise
		_cache[project] = (system.date.toMillis(system.date.now()), inv)
		return inv
	finally:
		_lock.unlock()


def _others():
	me = system.project.getProjectName()
	return [n for n in sorted(system.project.getProjectNames()) if n != me]


def projects():
	"""Dropdown options: every project on the gateway except this one, after the all-projects triage."""
	rows = [[ALL, 'All projects (triage)']] + [[n, n] for n in _others()]
	return system.dataset.toDataSet(['value', 'label'], rows)


def triage():
	"""One row per project with what needs looking at first. Scans every project, so the first call is slow."""
	out = []
	for name in _others():
		try:
			inv = load(name)
		except Exception as e:
			out.append({'project': name, 'title': '', 'enabled': '', 'pages': 0, 'views': 0, 'issues': 0, 'risks': 0,
				'background': 0, 'changed': 'scan failed: %s' % e})
			continue
		count = lambda cat: sum([len([r for r in v['rows'] if r['cat'] == cat]) for v in inv['views'].values()])
		meta = inv['meta']
		out.append({'project': name, 'title': meta['title'] or '', 'enabled': meta['enabled'], 'pages': len(inv['pages']),
			'views': len([v for v in inv['views'] if not v.startswith(inspector.scan.PSEUDO)]),
			'issues': count('issue'), 'risks': count('risk'), 'background': len(inv['background']),
			'changed': inv['recent'][0]['detail'] if inv['recent'] else ''})
	return out


def tree(project):
	if not project or project == ALL:
		return []
	return load(project)['tree']


def pages(project):
	"""Every selectable tree node as dropdown options - the tree's keyboard route."""
	rows = []
	def walk(items, trail):
		for n in items:
			if n['data']:
				rows.append([n['data'], ' / '.join(trail + [n['label']])])
			walk(n['items'], trail + [n['label']] if not n['data'] else trail)
	walk(tree(project), [])
	return system.dataset.toDataSet(['value', 'label'], rows)


def detail(project, key, follow=True, cats=None, search=''):
	"""Header, per-category counts and the filtered rows for one tree node."""
	counts = dict([(c, 0) for c, _ in inspector.scan.CATEGORIES])
	empty = {'title': '', 'views': [], 'counts': counts, 'rows': [], 'total': 0}
	if not project or not key or project == ALL:
		return empty
	inv = load(project)
	if key == 'report:overview':
		return dict(empty, title='Overview')
	rows, views = inspector.scan.page_rows(inv, key, follow)
	needle = (search or '').strip().lower()
	shown = []
	for r in rows:
		if needle and needle not in (' '.join([r['view'], r['comp'], r['trigger'], r['target'], r['detail']])).lower():
			continue
		counts[r['cat']] += 1
		if cats is None or r['cat'] in cats:
			view = r['view']
			jump = inspector.scan.jump_key(inv, r)
			shown.append({'category': inspector.scan.CATEGORY_LABELS[r['cat']], 'view': view[1:] if view[:1] in '@#%' else view,
				'source': view, 'comp': r['comp'], 'trigger': r['trigger'], 'target': r['target'], 'detail': r['detail'],
				'bi': r.get('bi', -1), 'jump': '' if jump == key else jump})
	return {'title': inspector.scan.title_of(inv, key), 'views': [v for v in views if not v.startswith(inspector.scan.PSEUDO)],
		'counts': counts, 'rows': shown, 'total': len(rows)}


def script(project, source, bi):
	"""The whole script a row was found in."""
	if not project or not source:
		return ''
	try:
		return load(project)['views'][source]['rows'][int(bi)].get('script', '')
	except (KeyError, IndexError, ValueError, TypeError):
		return ''


def markdown(project, key, follow=True, cats=None):
	if not project or not key or project == ALL:
		return ''
	return inspector.scan.to_markdown(load(project), key, cats, follow)


def rescan(project):
	if project == ALL:
		_cache.clear()
	else:
		_cache.pop(project, None)
