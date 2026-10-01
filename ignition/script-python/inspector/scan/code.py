# Walks a Perspective project's views, page config, script library, named
# queries and gateway-side scripts, and lists everything each part does, one
# row per finding, plus the problems found between them.
#
# Plain Python that runs under the gateway's Jython 2.7 and under CPython 3,
# so nothing here may touch system.* or use Python 3-only syntax.
import gzip
import json
import re
from io import BytesIO

CATEGORIES = [
	('issue', 'Broken references'),
	('risk', 'Security & risk'),
	('api', 'API calls'),
	('nq', 'Named queries'),
	('sql', 'SQL'),
	('script', 'Project scripts'),
	('block', 'Script blocks'),
	('nav', 'Navigation'),
	('popup', 'Popups & docks'),
	('msg', 'Messages'),
	('embed', 'Embedded views'),
	('tag', 'Tags'),
	('change', 'Recent changes'),
]
CATEGORY_LABELS = dict(CATEGORIES)

REPORTS = [
	('report:overview', 'Overview'),
	('report:issue', 'Broken references'),
	('report:background', 'Runs without a page'),
	('report:risk', 'Security & risk'),
	('report:change', 'Recent changes'),
]

# Polling slower than these is ordinary (a clock, a slow refresh) and not reported.
POLL_FLOOR_MS = 5000
QUERY_POLL_FLOOR_S = 30

# A view key starting with one of these is not a Perspective view: '@' is a
# gateway-side script source, '#' is a script-library module, '%' is a named query.
BACKGROUND, LIBRARY, QUERY = '@', '#', '%'
PSEUDO = (BACKGROUND, LIBRARY, QUERY, '(')

# Where-used keys, 'use:<kind>:<name>'.
USE_KINDS = {'nq': 'named query', 'fn': 'script', 'view': 'view', 'msg': 'message', 'tag': 'tag'}

_STR = r'''(?:u|r)?("(?:[^"\\\n]|\\.)*"|'(?:[^'\\\n]|\\.)*')'''
_RE_STR = re.compile(_STR)
_RE_NQ = re.compile(r'system\.db\.runNamedQuery\s*\(')
_RE_SQL = re.compile(r'system\.db\.(run(?:Prep|SFPrep|Scalar|ScalarPrep|Update|)Query|runPrepUpdate|runSFPrepUpdate|runUpdateQuery)\s*\(')
_RE_RAW_SQL = re.compile(r'system\.db\.(runQuery|runUpdateQuery|runScalarQuery)\s*\(')
_RE_HTTP = re.compile(r'system\.net\.(http\w*)\s*\(')
_RE_NAV = re.compile(r'system\.perspective\.(navigate|navigateBack|navigateForward)\s*\(')
_RE_POPUP = re.compile(r'system\.perspective\.(openPopup|togglePopup|closePopup|openDock|toggleDock|closeDock|alterDock)\s*\(')
_RE_MSG = re.compile(r'system\.(?:perspective|util)\.sendMessage\s*\(')
_RE_TAG = re.compile(r'system\.tag\.(read\w*|write\w*|query\w*|browse\w*|configure|getConfiguration)\s*\(')
_RE_ACCESS = re.compile(r'\b([A-Za-z_]\w*(?:\.[A-Za-z_]\w*)+)\s*\(')
_RE_BARE = re.compile(r'(?<![\w.])([A-Za-z_]\w*)\s*\(')
_RE_DEF = re.compile(r'(?m)^def\s+([A-Za-z_]\w*)\s*\(')
_RE_TOP_NAME = re.compile(r'(?m)^(?:class\s+([A-Za-z_]\w*)|([A-Za-z_]\w*)\s*=)')
_RE_ALIAS = re.compile(r'(?m)^\s*([A-Za-z_]\w*)\s*=\s*([A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*)\s*$')
_RE_DANGER = re.compile(r'system\.util\.execute\s*\(|system\.file\.writeFile\s*\(|(?<![\w.])(?:exec|eval)\s*\(')
_RE_NOW = re.compile(r'now\s*\(\s*(\d*)\s*\)')
_RE_RUNSCRIPT_POLL = re.compile(r'runScript\s*\([^)]*,\s*(\d+)\s*(?:,|\))')
_SECRETS = [
	(re.compile(r'-----BEGIN [A-Z ]*PRIVATE KEY-----(?:\\n|\s)*[A-Za-z0-9+/=]{40}'), 'private key'),
	(re.compile(r'\bpat-[a-z]{2}\d?-[0-9a-f-]{20,}'), 'HubSpot private-app token'),
	(re.compile(r'\bxox[abposr]-[A-Za-z0-9-]{10,}'), 'Slack token'),
	(re.compile(r'\bAKIA[0-9A-Z]{16}\b'), 'AWS access key'),
	(re.compile(r'\bAIza[0-9A-Za-z_-]{35}\b'), 'Google API key'),
	(re.compile(r'''Bearer\s+[A-Za-z0-9._~+/-]{20,}'''), 'bearer token'),
	(re.compile(r'''(?i)\b(password|passwd|pwd|secret|client_secret|api_?key|access_?token|token)\b['"]?\s*[:=]\s*['"][^'"\s]{6,}['"]'''), 'credential'),
]


def _literals(args):
	return [m.group(1)[1:-1] for m in _RE_STR.finditer(args)]


def _args_after(code, pos):
	# The text of a call's argument list, up to its closing bracket.
	depth, i = 1, pos
	while i < len(code) and depth:
		c = code[i]
		if c in '([{':
			depth += 1
		elif c in ')]}':
			depth -= 1
		i += 1
	return code[pos:i - 1]


def _kwarg(args, name):
	m = re.search(r'\b' + name + r'\s*=\s*' + _STR, args)
	return m.group(1)[1:-1] if m else None


def _line_of(code, pos):
	start = code.rfind('\n', 0, pos) + 1
	end = code.find('\n', pos)
	return code[start:end if end >= 0 else len(code)].strip()


def _summary(code):
	for line in code.split('\n'):
		s = line.strip()
		if s and not s.startswith('#'):
			return s[:160]
	return ''


def _route_matches(route, target):
	# '/sa/qs/processing/:document/:revision' matches '/sa/qs/processing/Q1/2'.
	a = [s for s in route.split('/') if s]
	b = [s for s in target.split('?')[0].split('/') if s]
	if len(a) != len(b):
		return False
	for x, y in zip(a, b):
		if not x.startswith(':') and x != y and not y.startswith('{'):
			return False
	return True


def _seconds(ms):
	return ('%g s' % (ms / 1000.0)) if ms >= 1000 else ('%d ms' % ms)


class Scanner(object):
	"""views: {'Plant/Overview': viewDict}, pageConfig: page-config dict,
	scripts: {'apis/weather': code}, namedQueries: {'plant/getBatches': {'sql', 'database', 'params'}},
	background: [{'id', 'kind', 'name', 'detail', 'scripts': [(trigger, code)], 'handlers': [type]}]."""

	def __init__(self, views, pageConfig, scripts, namedQueries=None, background=None):
		self.views = views
		self.pageConfig = pageConfig or {}
		self.scripts = scripts
		self.namedQueries = namedQueries or {}
		self.background = background or []
		self.modules = sorted([p.replace('/', '.') for p in scripts], key=len, reverse=True)
		self.roots = set([m.split('.')[0] for m in self.modules])
		self.functions = self._functions()
		self.topNames = self._top_names()
		self.apiFunctions = self._api_functions()
		self.apiModules = sorted(set([f.rsplit('.', 1)[0] for f in self.apiFunctions]))

	def _module_of(self, dotted):
		for m in self.modules:
			if dotted == m or dotted.startswith(m + '.'):
				return m
		return None

	def _functions(self):
		# Top-level functions of every module, 'apis.weather.getForecast' -> body.
		out = {}
		for path, code in self.scripts.items():
			mod = path.replace('/', '.')
			parts = _RE_DEF.split(code)
			for i in range(1, len(parts), 2):
				out[mod + '.' + parts[i]] = parts[i + 1]
		return out

	def _top_names(self):
		# Everything a module defines at top level, so a class or an assigned
		# callable is not reported as a missing function.
		out = set(self.functions)
		for path, code in self.scripts.items():
			mod = path.replace('/', '.')
			for m in _RE_TOP_NAME.finditer(code):
				out.add(mod + '.' + (m.group(1) or m.group(2)))
		return out

	def _api_functions(self):
		# A function is an API call if it calls out over HTTP itself, or calls a
		# function that does - so a thin wrapper counts as well as the helper.
		calls, api = {}, set()
		for name, body in self.functions.items():
			mod = name.rsplit('.', 1)[0]
			if _RE_HTTP.search(body):
				api.add(name)
			used = set()
			for m in _RE_ACCESS.finditer(body):
				if m.group(1) in self.functions:
					used.add(m.group(1))
			for m in _RE_BARE.finditer(body):
				if mod + '.' + m.group(1) in self.functions:
					used.add(mod + '.' + m.group(1))
			calls[name] = used
		changed = True
		while changed:
			changed = False
			for name, used in calls.items():
				if name not in api and used & api:
					api.add(name)
					changed = True
		return api

	def scan(self):
		views = {}
		for path in sorted(self.views):
			views[path] = self._scan_view(path, self.views[path])
		for src in self.background:
			views[BACKGROUND + src['id']] = self._scan_background(src)
		for path in sorted(self.scripts):
			views[LIBRARY + path.replace('/', '.')] = self._scan_library(path, self.scripts[path])
		for path in sorted(self.namedQueries):
			nq = self.namedQueries[path]
			views[QUERY + path] = {'rows': [{'cat': 'nq', 'view': QUERY + path, 'comp': 'named query', 'trigger': 'definition',
				'target': path, 'detail': 'database %s' % (nq.get('database') or '(project default)'), 'bi': 0, 'script': nq.get('sql') or ''}],
				'links': [], 'sends': [], 'handlers': []}
		pages = []
		for route in sorted(self.pageConfig.get('pages', {})):
			cfg = self.pageConfig['pages'][route]
			docks = []
			for side, lst in (cfg.get('docks') or {}).items():
				# docks also holds cornerPriority, a string.
				for d in (lst if isinstance(lst, list) else []):
					if isinstance(d, dict) and d.get('viewPath'):
						docks.append(d['viewPath'])
			pages.append({'route': route, 'title': cfg.get('title') or '', 'view': cfg.get('viewPath') or '', 'docks': docks})
		shared = []
		for side, lst in (self.pageConfig.get('sharedDocks') or {}).items():
			if isinstance(lst, list):
				for d in lst:
					if d.get('viewPath'):
						shared.append({'id': d.get('id') or d['viewPath'], 'side': side, 'view': d['viewPath']})
		inv = {'views': views, 'pages': pages, 'sharedDocks': shared, 'apiModules': self.apiModules,
			'scripts': sorted(self.modules), 'namedQueries': sorted(self.namedQueries),
			'background': [dict((k, s[k]) for k in ('id', 'kind', 'name', 'detail')) for s in self.background],
			'componentTypes': self._component_types()}
		messages = set()
		for v in views.values():
			messages.update([h for h in v['handlers'] if h])
			messages.update([s[0] for s in v['sends']])
		inv['messages'] = sorted(messages)
		self._issues(inv)
		self._page_security(inv)
		inv['unreached'] = unreached(inv)
		return inv

	def _component_types(self):
		counts = {}
		def walk(c):
			t = c.get('type')
			if t:
				counts[t] = counts.get(t, 0) + 1
			for ch in c.get('children') or []:
				walk(ch)
		for v in self.views.values():
			walk(v.get('root') or {})
		return counts

	def _scan_view(self, viewPath, view):
		rows = []
		ctx = {'rows': rows, 'view': viewPath, 'sends': [], 'handlers': []}
		for key, pc in sorted((view.get('propConfig') or {}).items()):
			self._prop_config(ctx, '(view)', key, pc)
		self._events(ctx, '(view)', view.get('events') or {})
		root = view.get('root') or {}
		self._component(ctx, root, root.get('meta', {}).get('name', 'root'))
		return self._finish(ctx)

	def _scan_background(self, src):
		ctx = {'rows': [], 'view': BACKGROUND + src['id'], 'sends': [], 'handlers': []}
		for trigger, code in src.get('scripts') or []:
			self._code(ctx, src['kind'], trigger, code)
		for h in src.get('handlers') or []:
			self._add(ctx, 'msg', src['kind'], 'handler', h, 'receives')
			ctx['handlers'].append(h)
		return self._finish(ctx)

	def _scan_library(self, path, code):
		# Library modules are only checked for risk; what calls them is already
		# listed where it is called from.
		ctx = {'rows': [], 'view': LIBRARY + path.replace('/', '.'), 'sends': [], 'handlers': []}
		if code.strip():
			ctx['rows'].append({'cat': 'block', 'view': ctx['view'], 'comp': 'script library', 'trigger': path.replace('/', '.'),
				'target': '', 'detail': '%d lines' % code.count('\n'), 'bi': 0, 'script': code})
			self._risks(ctx, 'script library', path.replace('/', '.'), code, 0)
		return self._finish(ctx)

	def _finish(self, ctx):
		links = []
		for r in ctx['rows']:
			if r['cat'] in ('embed', 'popup') and r.get('viewLink') and r['viewLink'] not in links:
				links.append(r['viewLink'])
		return {'rows': ctx['rows'], 'links': links, 'sends': ctx['sends'], 'handlers': ctx['handlers']}

	def _add(self, ctx, cat, comp, trigger, target, detail='', block=None, viewLink=None):
		# Only a 'block' row carries its script; a call found inside it points
		# back at that row with 'bi', so each script is stored once.
		row = {'cat': cat, 'view': ctx['view'], 'comp': comp, 'trigger': trigger,
			'target': target or '', 'detail': detail or ''}
		if block is not None:
			row['bi'] = block
		if viewLink:
			row['viewLink'] = viewLink
		ctx['rows'].append(row)
		return row

	def _component(self, ctx, c, path):
		props = c.get('props') or {}
		ctype = c.get('type') or ''
		if ctype in ('ia.display.view', 'ia.display.flex-repeater'):
			bound = 'props.path' in (c.get('propConfig') or {})
			vp = props.get('path')
			if vp or bound:
				self._add(ctx, 'embed', path, ctype.split('.')[-1], vp or '(bound)',
					'path is bound' if bound else '', viewLink=None if bound else vp)
		elif ctype == 'ia.container.tab':
			for t in props.get('tabs') or []:
				if isinstance(t, dict) and t.get('viewPath'):
					self._add(ctx, 'embed', path, 'tab "%s"' % (t.get('text') or ''), t['viewPath'], viewLink=t['viewPath'])
		elif ctype == 'ia.display.table':
			for col in props.get('columns') or []:
				if isinstance(col, dict) and col.get('render') == 'view' and col.get('viewPath'):
					self._add(ctx, 'embed', path, 'column "%s"' % (col.get('field') or ''), col['viewPath'], 'table cell view', viewLink=col['viewPath'])
			sub = ((props.get('rows') or {}).get('subview') or {})
			if sub.get('enabled') and sub.get('viewPath'):
				self._add(ctx, 'embed', path, 'row subview', sub['viewPath'], viewLink=sub['viewPath'])
		elif ctype == 'ia.display.carousel':
			for t in props.get('views') or []:
				if isinstance(t, dict) and t.get('viewPath'):
					self._add(ctx, 'embed', path, 'carousel', t['viewPath'], viewLink=t['viewPath'])
		for key, pc in sorted((c.get('propConfig') or {}).items()):
			self._prop_config(ctx, path, key, pc)
		self._events(ctx, path, c.get('events') or {})
		scripts = c.get('scripts') or {}
		for h in scripts.get('messageHandlers') or []:
			scopes = [s for s in ('pageScope', 'sessionScope', 'viewScope') if h.get(s)]
			self._add(ctx, 'msg', path, 'handler', h.get('messageType'), 'receives (%s)' % ', '.join(scopes))
			ctx['handlers'].append(h.get('messageType'))
			self._code(ctx, path, 'message "%s"' % h.get('messageType'), h.get('script') or '')
		for m in scripts.get('customMethods') or []:
			self._code(ctx, path, 'method %s(%s)' % (m.get('name'), ', '.join(m.get('params') or [])), m.get('script') or '')
		ext = scripts.get('extensionFunctions') or {}
		for name, f in (ext.items() if isinstance(ext, dict) else []):
			if isinstance(f, dict) and f.get('enabled'):
				self._code(ctx, path, 'extension %s' % name, f.get('script') or '')
		for i, ch in enumerate(c.get('children') or []):
			name = (ch.get('meta') or {}).get('name') or ('child%d' % i)
			self._component(ctx, ch, path + '/' + name)

	def _prop_config(self, ctx, path, key, pc):
		b = pc.get('binding')
		if b:
			btype = b.get('type')
			cfg = b.get('config') or {}
			trig = 'binding %s' % key
			if btype == 'query':
				self._add(ctx, 'nq', path, trig, cfg.get('queryPath'), 'query binding')
				poll = cfg.get('polling') or {}
				rate = poll.get('rate')
				try:
					seconds = float(rate)
				except (TypeError, ValueError):
					seconds = 0
				# rate is seconds; an expression the scan cannot evaluate is reported as it stands.
				if poll.get('enabled') and seconds < QUERY_POLL_FLOOR_S:
					self._add(ctx, 'risk', path, trig, cfg.get('queryPath'), 'query runs every %s s' % rate)
			elif btype == 'tag':
				self._add(ctx, 'tag', path, trig, cfg.get('tagPath'), 'tag binding (%s)' % cfg.get('mode', 'direct'))
			elif btype == 'tag-history':
				self._add(ctx, 'tag', path, trig, ', '.join([str(t.get('path')) for t in cfg.get('tags') or [] if isinstance(t, dict)]), 'tag history binding')
			elif btype == 'http':
				self._add(ctx, 'api', path, trig, cfg.get('url'), 'HTTP binding %s' % (cfg.get('method') or ''))
			exprs = []
			if btype == 'expr':
				exprs.append(cfg.get('expression') or '')
			elif btype == 'expr-struct':
				exprs.extend([v for v in (cfg.get('struct') or {}).values() if hasattr(v, 'strip')])
			for e in exprs:
				self._expression_risks(ctx, path, trig, e)
			for t in b.get('transforms') or []:
				if t.get('type') == 'script':
					self._code(ctx, path, 'transform on %s' % key, t.get('code') or '')
				elif t.get('type') == 'expression':
					self._expression_risks(ctx, path, trig, t.get('expression') or '')
		if pc.get('onChange') and pc['onChange'].get('script'):
			self._code(ctx, path, 'onChange %s' % key, pc['onChange']['script'])

	def _expression_risks(self, ctx, path, trigger, expr):
		for m in _RE_NOW.finditer(expr):
			ms = int(m.group(1)) if m.group(1) else 1000
			if 0 < ms < POLL_FLOOR_MS:
				self._add(ctx, 'risk', path, trigger, expr[:80], 'expression re-runs every %s via now()' % _seconds(ms))
		for m in _RE_RUNSCRIPT_POLL.finditer(expr):
			ms = int(m.group(1))
			if 0 < ms < POLL_FLOOR_MS:
				self._add(ctx, 'risk', path, trigger, expr[:80], 'runScript re-runs every %s' % _seconds(ms))

	def _events(self, ctx, path, events):
		for cat in sorted(events):
			for name in sorted(events[cat]):
				acts = events[cat][name]
				for a in (acts if isinstance(acts, list) else [acts]):
					if not isinstance(a, dict):
						continue
					t, cfg = a.get('type'), a.get('config') or {}
					if t == 'script':
						self._code(ctx, path, name, cfg.get('script') or '')
					elif t == 'nav':
						self._add(ctx, 'nav', path, name, cfg.get('page') or cfg.get('url') or cfg.get('view'), 'navigate action')
					elif t == 'popup':
						self._add(ctx, 'popup', path, name, cfg.get('viewPath') or cfg.get('id'), 'popup %s' % (cfg.get('type') or 'open'), viewLink=cfg.get('viewPath'))
					elif t == 'dock':
						self._add(ctx, 'popup', path, name, cfg.get('id'), 'dock %s' % (cfg.get('type') or ''))
					elif t:
						self._add(ctx, 'block', path, name, t, '%s action' % t)

	def _code(self, ctx, path, trigger, code):
		if not code.strip():
			return
		bi = len(ctx['rows'])
		self._add(ctx, 'block', path, trigger, '', _summary(code), bi)['script'] = code
		code = code.replace('\r\n', '\n')
		aliases = {}
		for m in _RE_ALIAS.finditer(code):
			if m.group(2).split('.')[0] in self.roots:
				aliases[m.group(1)] = m.group(2)
		for m in _RE_NQ.finditer(code):
			args = _args_after(code, m.end())
			lits = _literals(args)
			q = _kwarg(args, 'path')
			if not q and lits:
				# Gateway scope passes the project first: ("proj", "folder/query").
				q = lits[1] if len(lits) > 1 and '/' not in lits[0] and '/' in lits[1] else lits[0]
			self._add(ctx, 'nq', path, trigger, q or '(dynamic)', _line_of(code, m.start()), bi)
		for m in _RE_SQL.finditer(code):
			self._add(ctx, 'sql', path, trigger, 'system.db.' + m.group(1), _line_of(code, m.start()), bi)
		for m in _RE_HTTP.finditer(code):
			self._add(ctx, 'api', path, trigger, 'system.net.' + m.group(1), _line_of(code, m.start()), bi)
		for m in _RE_NAV.finditer(code):
			args = _args_after(code, m.end())
			lits = _literals(args)
			self._add(ctx, 'nav', path, trigger, _kwarg(args, 'page') or _kwarg(args, 'view') or _kwarg(args, 'url') or (lits[0] if lits else '(dynamic)'), _line_of(code, m.start()), bi)
		for m in _RE_POPUP.finditer(code):
			fn = m.group(1)
			args = _args_after(code, m.end())
			lits = _literals(args)
			vp = None
			if fn in ('openPopup', 'togglePopup'):
				vp = _kwarg(args, 'view') or (lits[1] if len(lits) > 1 else None)
			target = vp or _kwarg(args, 'id') or (lits[0] if lits else '(dynamic)')
			self._add(ctx, 'popup', path, trigger, target, _line_of(code, m.start()), bi, viewLink=vp)
		for m in _RE_MSG.finditer(code):
			args = _args_after(code, m.end())
			lits = _literals(args)
			mtype = _kwarg(args, 'messageType') or (lits[0] if lits else None)
			self._add(ctx, 'msg', path, trigger, mtype or '(dynamic)', 'sends: ' + _line_of(code, m.start()), bi)
			if mtype:
				ctx['sends'].append((mtype, path, trigger, bi))
		for m in _RE_TAG.finditer(code):
			args = _args_after(code, m.end())
			lits = _literals(args)
			self._add(ctx, 'tag', path, trigger, lits[0] if lits else '(dynamic)', _line_of(code, m.start()), bi)
		seen = set()
		for m in _RE_ACCESS.finditer(code):
			dotted = m.group(1)
			head, _, rest = dotted.partition('.')
			if head in aliases:
				dotted = aliases[head] + '.' + rest
			if dotted.split('.')[0] not in self.roots or dotted in seen:
				continue
			seen.add(dotted)
			mod = self._module_of(dotted)
			if not mod:
				self._add(ctx, 'issue', path, trigger, dotted, 'no script module %s in this project' % '.'.join(dotted.split('.')[:-1]), bi)
				continue
			if dotted != mod and dotted.count('.') == mod.count('.') + 1 and dotted not in self.topNames:
				self._add(ctx, 'issue', path, trigger, dotted, '%s has no function %s' % (mod, dotted.rsplit('.', 1)[1]), bi)
				continue
			cat = 'api' if dotted in self.apiFunctions else 'script'
			self._add(ctx, cat, path, trigger, dotted, _line_of(code, m.start()), bi)
		self._risks(ctx, path, trigger, code, bi)

	def _risks(self, ctx, path, trigger, code, bi):
		for rx, what in _SECRETS:
			m = rx.search(code)
			if m:
				self._add(ctx, 'risk', path, trigger, what, 'hard-coded %s on line %d (value hidden)' % (what, code.count('\n', 0, m.start()) + 1), bi)
		for m in _RE_DANGER.finditer(code):
			self._add(ctx, 'risk', path, trigger, m.group(0).rstrip('( '), 'runs a command or arbitrary code: ' + _line_of(code, m.start())[:120], bi)
		for m in _RE_RAW_SQL.finditer(code):
			args = _args_after(code, m.end())
			first = args.split(',')[0]
			if re.search(r"%|\+|\.format\s*\(|\bf['\"]", first) or (not _RE_STR.match(first.strip()) and first.strip()):
				self._add(ctx, 'risk', path, trigger, 'system.db.' + m.group(1), 'SQL built from strings, not parameters: ' + _line_of(code, m.start())[:120], bi)

	def _issues(self, inv):
		views = inv['views']
		real = set([v for v in views if not v.startswith(PSEUDO)])
		handlers, sends = {}, {}
		for key, v in views.items():
			for h in v['handlers']:
				handlers.setdefault(h, []).append(key)
			for s in v['sends']:
				sends.setdefault(s[0], []).append((key, s))
		for key, v in views.items():
			extra = []
			for r in v['rows']:
				if r['cat'] == 'nq' and r['target'] and r['target'] not in ('(dynamic)',) \
						and r['target'] not in self.namedQueries and not r['target'].startswith('{'):
					extra.append(dict(r, cat='issue', detail='no named query %s in this project' % r['target']))
				if r.get('viewLink') and r['viewLink'] not in real and not r['viewLink'].startswith('{'):
					extra.append(dict(r, cat='issue', detail='no view %s in this project' % r['viewLink']))
				if r['cat'] == 'nav' and r['target'].startswith('/') and '{' not in r['target'] \
						and not [p for p in inv['pages'] if _route_matches(p['route'], r['target'])]:
					extra.append(dict(r, cat='issue', detail='no page route matches %s' % r['target']))
				if r['cat'] == 'msg' and r['trigger'] == 'handler' and r['target'] not in sends \
						and not self._mentioned(r['target']):
					extra.append(dict(r, cat='issue', detail='nothing in this project sends "%s" (it may come from another project)' % r['target']))
			for mtype, path, trigger, bi in v['sends']:
				if mtype not in handlers:
					extra.append({'cat': 'issue', 'view': key, 'comp': path, 'trigger': trigger, 'target': mtype,
						'detail': 'nothing in this project handles "%s"' % mtype, 'bi': bi})
			v['rows'].extend(extra)
		for p in inv['pages']:
			if not p['view'] or p['view'] not in real:
				host = p['view'] if p['view'] in views else None
				row = {'cat': 'issue', 'view': host or '(page config)', 'comp': 'page config', 'trigger': 'route',
					'target': p['route'], 'detail': 'route points at %s, which does not exist' % (p['view'] or 'no view')}
				views.setdefault('(page config)', {'rows': [], 'links': [], 'sends': [], 'handlers': []})['rows'].append(row)
		for d in inv['sharedDocks']:
			if d['view'] not in real:
				views.setdefault('(page config)', {'rows': [], 'links': [], 'sends': [], 'handlers': []})['rows'].append(
					{'cat': 'issue', 'view': '(page config)', 'comp': 'shared dock', 'trigger': d['id'], 'target': d['view'],
					 'detail': 'shared dock points at %s, which does not exist' % d['view']})
		for name, nq in self.namedQueries.items():
			for prm in nq.get('params') or []:
				if prm.get('type') == 'QueryString':
					views.setdefault('(named queries)', {'rows': [], 'links': [], 'sends': [], 'handlers': []})['rows'].append(
						{'cat': 'risk', 'view': '(named queries)', 'comp': 'named query', 'trigger': name, 'target': prm.get('identifier', ''),
						 'detail': 'QueryString parameter is pasted into the SQL as text (injection risk)'})

	def _mentioned(self, text):
		# A handler whose type is passed around as data (a confirm popup told
		# which message to send back) has no literal sendMessage; any other
		# mention of the name counts as a possible sender.
		if not hasattr(self, '_corpus'):
			parts = [json.dumps(v) for v in self.views.values()] + list(self.scripts.values())
			parts.extend([code for b in self.background for _, code in b.get('scripts') or []])
			self._corpus = '\n'.join(parts)
		quoted = [q % text for q in ('"%s"', "'%s'", '\\"%s\\"')]
		return sum([self._corpus.count(q) for q in quoted]) >= 2

	def _page_security(self, inv):
		for p in inv['pages']:
			v = self.views.get(p['view'])
			if v is None:
				continue
			levels = ((v.get('permissions') or {}).get('securityLevels') or [])
			if not levels:
				inv['views'][p['view']]['rows'].append({'cat': 'risk', 'view': p['view'], 'comp': '(view)', 'trigger': 'permissions',
					'target': p['route'], 'detail': 'page view has no security levels - any signed-in user can open it'})


_KINDS = {
	('ignition', 'timer'): 'Timer script',
	('ignition', 'scheduled'): 'Scheduled script',
	('ignition', 'startup'): 'Gateway startup',
	('ignition', 'shutdown'): 'Gateway shutdown',
	('ignition', 'update'): 'Project update',
	('ignition', 'tag-change'): 'Tag change script',
	('ignition', 'message'): 'Gateway message handler',
	('ignition', 'event-scripts'): 'Gateway events (8.1 format)',
	('com.inductiveautomation.perspective', 'session-scripts'): 'Perspective session events',
	('com.inductiveautomation.webdev', 'resources'): 'Web endpoint',
}
_NOT_BACKGROUND = set(['script-python', 'named-query', 'views', 'page-config', 'session-props', 'stylesheet',
	'style-classes', 'general-properties', 'global-props', 'designer-properties', 'inactivity-properties',
	'session-permissions', 'tag-drop-settings', 'auth-challenge', 'client-tags', 'polling-properties', 'reports'])
_RE_CRON = re.compile(r'^[\d*/,\-]+( +[\d*/,\-]+){4}$')
_RE_IDENT = re.compile(r'^[A-Za-z_][\w ]{2,60}$')


def background_source(moduleId, rtype, path, files, attrs):
	"""A gateway-side script resource as a background source, or None.

	files maps each data file name to its text; binary files arrive as
	latin-1 text so each character is one byte. attrs is the resource's
	attribute dict."""
	if rtype in _NOT_BACKGROUND:
		return None
	kind = _KINDS.get((moduleId, rtype), '%s %s' % (moduleId.split('.')[-1], rtype))
	name = path or rtype
	src = {'id': '%s/%s' % (rtype, name), 'kind': kind, 'name': name, 'detail': _attr_detail(attrs), 'scripts': [], 'handlers': []}
	if rtype == 'message':
		src['handlers'].append(name)
	# A web endpoint ships a stub for every HTTP method; only the enabled ones answer.
	config = {}
	if files.get('config.json'):
		try:
			config = json.loads(files['config.json'])
		except ValueError:
			config = {}
	for fname in sorted(files):
		text = files[fname]
		if fname.endswith('.py'):
			method = config.get(fname[:-3])
			if isinstance(method, dict) and method.get('enabled') is False:
				continue
			if text.strip() and text.strip() not in ('pass',):
				src['scripts'].append((fname[:-3], text))
		elif fname == 'data.bin':
			if text.lstrip().startswith('{'):
				_session_json(src, json.loads(text))
			else:
				_legacy_blob(src, text)
	if not src['scripts'] and not src['handlers']:
		return None
	return src


def _attr_detail(attrs):
	bits = []
	if 'enabled' in attrs and str(attrs['enabled']).lower() == 'false':
		bits.append('disabled')
	if attrs.get('delay'):
		bits.append('every %s' % _seconds(int(float(str(attrs['delay'])))))
	for key in ('cronExpression', 'cron'):
		if attrs.get(key):
			bits.append('cron %s' % attrs[key])
	if attrs.get('paths'):
		bits.append('tags %s' % str(attrs['paths']).strip('[]').replace('"', ''))
	return ', '.join(bits)


def _session_json(src, doc):
	for key, val in sorted(doc.items()):
		if key == 'messageHandlers':
			for h in val or []:
				if h.get('enabled', True) is not False:
					src['handlers'].append(h.get('name') or h.get('messageType'))
					if (h.get('script') or '').strip():
						src['scripts'].append(('message "%s"' % (h.get('name') or ''), h['script']))
		elif hasattr(val, 'strip') and val.strip():
			src['scripts'].append((key, val))


def _legacy_blob(src, text):
	# The 8.1 event-scripts blob is gzipped Java serialisation. Script text,
	# names and cron strings survive as printable runs, which is enough to
	# list what runs and what it calls; the pairing of name to script is a
	# best guess from their order.
	try:
		raw = gzip.GzipFile(fileobj=BytesIO(text.encode('latin-1'))).read()
	except Exception:
		return
	runs = [r for r in re.split(r'[^\x20-\x7e\t\n\r]+', raw.decode('latin-1')) if len(r.strip()) >= 4]
	label, crons = 'script', []
	for r in runs:
		t = r.strip()
		if _RE_CRON.match(t.lstrip('| ')):
			crons.append(t.lstrip('| '))
			label = 'cron %s' % t.lstrip('| ')
		elif '(' in t and ('\t' in r or '\n' in r or t.startswith('def ')):
			# A one- or two-byte length prefix that happens to be printable.
			m = re.match(r'^[^\t\n]{1,2}(?=\t|def )', r)
			src['scripts'].append((label, r[m.end():] if m else r))
			label = 'script'
		elif _RE_IDENT.match(t) and ' ' not in t:
			label = t
	src['detail'] = 'decoded from the 8.1 binary format; names approximate' + ('; schedules ' + ', '.join(crons) if crons else '')


def view_closure(inv, viewPath, follow=True):
	"""The view and, when follow is set, every view it embeds or opens."""
	out, todo = [], [viewPath]
	while todo:
		v = todo.pop(0)
		if v in out or v not in inv['views']:
			continue
		out.append(v)
		if follow:
			todo.extend(inv['views'][v]['links'])
	return out


def unreached(inv):
	reached = set()
	for p in inv['pages']:
		for v in [p['view']] + p['docks']:
			reached.update(view_closure(inv, v))
	for d in inv['sharedDocks']:
		reached.update(view_closure(inv, d['view']))
	for k in inv['views']:
		if k.startswith(PSEUDO):
			for link in inv['views'][k]['links']:
				reached.update(view_closure(inv, link))
	return sorted([v for v in inv['views'] if v not in reached and not v.startswith(PSEUDO)])


def where_used(inv, kind, name):
	"""The definition of a named query, script, view, message type or tag, then everything that uses it."""
	defs, uses = [], []
	module = name if (LIBRARY + name) in inv['views'] else name.rsplit('.', 1)[0]
	for k in sorted(inv['views']):
		for r in inv['views'][k]['rows']:
			t = r['target']
			if kind == 'nq':
				if k == QUERY + name:
					defs.append(r)
				elif r['cat'] in ('nq', 'issue') and t == name:
					uses.append(r)
			elif kind == 'fn':
				if k == LIBRARY + module and r['cat'] == 'block':
					defs.append(r)
				elif r['cat'] in ('script', 'api', 'issue') and (t == name or t.startswith(name + '.')):
					uses.append(r)
			elif kind == 'view':
				if r.get('viewLink') == name or (r['cat'] == 'embed' and t == name):
					uses.append(r)
			elif r['cat'] in (kind, 'issue') and t == name:
				uses.append(r)
	if kind == 'view':
		for p in inv['pages']:
			if name == p['view'] or name in p['docks']:
				uses.append({'cat': 'nav', 'view': '(page config)', 'comp': 'page config', 'trigger': 'route' if name == p['view'] else 'dock',
					'target': p['route'], 'detail': 'page view' if name == p['view'] else 'dock on this page'})
		for d in inv['sharedDocks']:
			if d['view'] == name:
				uses.append({'cat': 'popup', 'view': '(page config)', 'comp': 'shared dock', 'trigger': d['id'], 'target': name, 'detail': 'shared dock (%s)' % d['side']})
	return defs + uses


def jump_key(inv, r):
	"""The tree key a finding points at: the view it opens, the page it goes to, or where its target is defined and used."""
	cat, t, link = r['cat'], r['target'] or '', r.get('viewLink')
	literal = t and '(dynamic)' not in t and '{' not in t
	if cat == 'issue':
		d = r['detail']
		if d.startswith('no named query'):
			return 'use:nq:' + t
		if d.startswith('no view'):
			return 'use:view:' + link if link else ''
		if d.startswith(('nothing in this project sends', 'nothing in this project handles')):
			return 'use:msg:' + t
		if d.startswith('no script module') or ' has no function ' in d:
			return 'use:fn:' + t
		if d.startswith('no tag'):
			return 'use:tag:' + t
		return ''
	if link and link in inv['views']:
		return 'view:' + link
	if cat in ('embed', 'popup') and t in inv['views'] and not t.startswith(PSEUDO):
		return 'view:' + t
	if cat == 'nav' and t.startswith('/'):
		for p in inv['pages']:
			if p['route'] == t or _route_matches(p['route'], t):
				return 'route:' + p['route']
		return ''
	if not literal:
		return ''
	if cat == 'nq':
		return 'use:nq:' + t
	if cat in ('script', 'api') and not t.startswith('system.'):
		return 'use:fn:' + t
	if cat in ('msg', 'tag'):
		return 'use:%s:%s' % (cat, t)
	return ''


def page_rows(inv, key, follow=True):
	"""Rows for a tree key: 'route:/x', 'dock:<id>', 'view:<path>', 'use:<kind>:<name>' or 'report:<kind>'."""
	kind, _, val = key.partition(':')
	if kind == 'use':
		ukind, _, name = val.partition(':')
		return where_used(inv, ukind, name), []
	if kind == 'report':
		if val == 'background':
			keys = sorted([k for k in inv['views'] if k.startswith(BACKGROUND)])
			rows = []
			for k in keys:
				rows.extend(inv['views'][k]['rows'])
			return rows, keys
		if val == 'change':
			return list(inv.get('recent') or []), []
		rows = []
		for k in sorted(inv['views']):
			rows.extend([r for r in inv['views'][k]['rows'] if r['cat'] == val])
		return rows, []
	starts = []
	if kind == 'route':
		for p in inv['pages']:
			if p['route'] == val:
				starts = [p['view']] + p['docks']
	elif kind == 'dock':
		starts = [d['view'] for d in inv['sharedDocks'] if d['id'] == val]
	else:
		starts = [val]
	views = []
	for s in starts:
		for v in view_closure(inv, s, follow):
			if v not in views:
				views.append(v)
	rows = []
	for v in views:
		rows.extend(inv['views'][v]['rows'])
	return rows, views


def title_prefix(inv):
	# 'Plant - Overview', 'Plant - Alarms' -> 'Plant - ', so titles show what differs.
	titles = [p['title'] for p in inv['pages'] if p['title']]
	if len(titles) < 3:
		return ''
	first, last = min(titles), max(titles)
	i = 0
	while i < len(first) and i < len(last) and first[i] == last[i]:
		i += 1
	cut = max(first.rfind(' ', 0, i + 1), first.rfind('-', 0, i + 1))
	return first[:cut + 1] if cut >= 3 else ''


def title_of(inv, key):
	kind, _, val = key.partition(':')
	if kind == 'route':
		for p in inv['pages']:
			if p['route'] == val:
				return '%s  %s' % (p['title'][len(title_prefix(inv)):] or val, val)
	if kind == 'report':
		return dict(REPORTS).get(key, val)
	if kind == 'use':
		ukind, _, name = val.partition(':')
		return 'Where used: %s %s' % (USE_KINDS.get(ukind, ukind), name)
	if kind == 'view' and val.startswith(BACKGROUND):
		return val[1:]
	return val


def overview(inv):
	"""The project at a glance, as Markdown."""
	count = lambda cat: sum([len([r for r in v['rows'] if r['cat'] == cat]) for v in inv['views'].values()])
	real = [v for v in inv['views'] if not v.startswith(PSEUDO)]
	meta = inv.get('meta') or {}
	out = ['# %s' % (meta.get('title') or inv.get('name', '')), '']
	if meta.get('description'):
		out.extend([meta['description'], ''])
	facts = [('Project', inv.get('name', '')), ('Enabled', meta.get('enabled', '')),
		('Inherits from', meta.get('parent') or 'nothing'), ('Page routes', len(inv['pages'])),
		('Views', len(real)), ('Views no page reaches', len(inv['unreached'])),
		('Script modules', len(inv['scripts'])), ('Named queries', len(inv['namedQueries'])),
		('Gateway-side scripts', len(inv['background'])),
		('Broken references', count('issue')), ('Security & risk findings', count('risk'))]
	out.extend(['| Item | Value |', '| :-- | :-- |'] + ['| %s | %s |' % f for f in facts] + [''])
	if inv['background']:
		out.extend(['## Runs without a page', '', '| Kind | Name | Detail |', '| :-- | :-- | :-- |'])
		out.extend(['| %s | %s | %s |' % (b['kind'], b['name'], b['detail'] or '') for b in inv['background']])
		out.append('')
	if inv['apiModules']:
		out.extend(['## Script modules that call external APIs', '', ', '.join(['`%s`' % m for m in inv['apiModules']]), ''])
	third = sorted([(t, n) for t, n in inv.get('componentTypes', {}).items() if not t.startswith('ia.')])
	if third:
		out.extend(['## Components from other modules', '', 'The gateway needs these modules installed for the pages to render.', ''])
		out.extend(['- `%s` (%d)' % (t, n) for t, n in third] + [''])
	dbs = sorted(set([d for d in (inv.get('databases') or []) if d]))
	if dbs:
		out.extend(['## Databases named by its queries', '', ', '.join(['`%s`' % d for d in dbs]), ''])
	providers = set()
	for v in inv['views'].values():
		for r in v['rows']:
			if r['cat'] == 'tag':
				m = re.match(r'\[([^\]]*)\]', r['target'])
				if m:
					providers.add(m.group(1) or '(default)')
	if providers:
		out.extend(['## Tag providers referenced', '', ', '.join(['`%s`' % p for p in sorted(providers)]), ''])
	return '\n'.join(out)


def to_markdown(inv, key, cats=None, follow=True):
	"""One tree node's findings as Markdown - tables per category, scripts omitted."""
	if key == 'report:overview':
		return overview(inv)
	rows, views = page_rows(inv, key, follow)
	out = ['# ' + title_of(inv, key), '']
	if views:
		out.extend(['Views: ' + ', '.join(['`%s`' % v for v in views]), ''])
	for cat, label in CATEGORIES:
		if cats is not None and cat not in cats:
			continue
		sub = [r for r in rows if r['cat'] == cat]
		if not sub:
			continue
		out.extend(['## %s (%d)' % (label, len(sub)), ''])
		out.append('| View | Component | Trigger | Target | Detail |')
		out.append('| :-- | :-- | :-- | :-- | :-- |')
		for r in sub:
			cells = [r['view'], r['comp'], r['trigger'], r['target'], r['detail']]
			out.append('| ' + ' | '.join([('`%s`' % c.replace('|', '\\|')) if i == 3 and c else c.replace('|', '\\|') for i, c in enumerate(cells)]) + ' |')
		out.append('')
	return '\n'.join(out)
