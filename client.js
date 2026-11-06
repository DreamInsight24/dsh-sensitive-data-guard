// 敏感数据守卫 —— DSH 设置页（Client 半）。
//
// 只做两件事：改「提醒级别」、维护「保护目录」，保存后立即生效。
// 数据通道走 Host 半注册的同源 JSON 路由；放宽级别时红字警告但不拦截。
window.__ModuleLoader__.load({
  id: '@local/dsh-sensitive-data-guard',
  factory(require) {
    const React = require('react');
    const h = React.createElement;
    const { useCallback, useEffect, useMemo, useState } = React;

    const API = '/plugins/dsh-sensitive-data-guard/settings';

    const LEVEL_LABEL = { soft: 'soft（仅备份）', medium: 'medium（按阈值）', hard: 'hard（最严）' };
    const LEVEL_ORDER = ['soft', 'medium', 'hard'];

    const S = {
      root: { display: 'grid', gap: '18px', maxWidth: '760px', padding: '4px 0 24px' },
      h1: { fontSize: '16px', fontWeight: 600, margin: 0 },
      lead: { fontSize: '12px', lineHeight: 1.6, opacity: 0.72, margin: '6px 0 0' },
      card: { border: '1px solid rgba(127,127,127,0.28)', borderRadius: '10px', padding: '14px 16px', display: 'grid', gap: '12px' },
      legend: { fontSize: '13px', fontWeight: 600, margin: 0 },
      option: { display: 'grid', gridTemplateColumns: 'auto 1fr', gap: '10px', alignItems: 'start', cursor: 'pointer' },
      optionText: { display: 'grid', gap: '3px' },
      small: { fontSize: '11px', lineHeight: 1.55, opacity: 0.7 },
      tiny: { fontSize: '11px', lineHeight: 1.6, opacity: 0.6 },
      row: { display: 'flex', gap: '10px', alignItems: 'center', flexWrap: 'wrap' },
      num: { width: '132px', padding: '6px 8px', borderRadius: '6px', border: '1px solid rgba(127,127,127,0.35)', background: 'transparent', color: 'inherit', fontSize: '12px' },
      textarea: { width: '100%', minHeight: '132px', boxSizing: 'border-box', padding: '10px', borderRadius: '8px', border: '1px solid rgba(127,127,127,0.35)', background: 'transparent', color: 'inherit', fontFamily: 'ui-monospace, SFMono-Regular, Menlo, monospace', fontSize: '12px', lineHeight: 1.6, resize: 'vertical' },
      button: { padding: '7px 16px', borderRadius: '7px', border: '1px solid rgba(127,127,127,0.4)', background: 'rgba(127,127,127,0.12)', color: 'inherit', fontSize: '12px', fontWeight: 600, cursor: 'pointer' },
      buttonPrimary: { padding: '7px 16px', borderRadius: '7px', border: '1px solid #2f7dd1', background: '#2f7dd1', color: '#fff', fontSize: '12px', fontWeight: 600, cursor: 'pointer' },
      warn: { fontSize: '12px', lineHeight: 1.6, color: '#d4380d', border: '1px solid rgba(212,56,13,0.45)', background: 'rgba(212,56,13,0.08)', borderRadius: '8px', padding: '10px 12px' },
      ok: { fontSize: '12px', color: '#237804' },
      err: { fontSize: '12px', color: '#d4380d' },
      kv: { display: 'grid', gridTemplateColumns: 'auto 1fr', gap: '4px 12px', fontSize: '11px', opacity: 0.72 },
    };

    function Section({ embedded = false } = {}) {
      const [loading, setLoading] = useState(true);
      const [settings, setSettings] = useState(null);
      const [level, setLevel] = useState('hard');
      const [minFiles, setMinFiles] = useState('10');
      const [minBytes, setMinBytes] = useState('67108864');
      const [paths, setPaths] = useState('');
      const [saving, setSaving] = useState(false);
      const [notice, setNotice] = useState(null);

      const load = useCallback(async () => {
        setLoading(true);
        try {
          const response = await fetch(API, { method: 'GET', headers: { accept: 'application/json' } });
          const body = await response.json();
          if (!body.ok) throw new Error(body.error || '读取失败');
          const s = body.settings;
          setSettings(s);
          setLevel(s.triggerLevel);
          setMinFiles(String(s.mediumMinFiles));
          setMinBytes(String(s.mediumMinBytes));
          setPaths((s.protectedPaths || []).join('\n'));
        } catch (error) {
          setNotice({ kind: 'err', text: `读取设置失败：${error.message}` });
        } finally {
          setLoading(false);
        }
      }, []);

      useEffect(() => { load(); }, [load]);

      const dirty = useMemo(() => {
        if (!settings) return false;
        return level !== settings.triggerLevel
          || minFiles !== String(settings.mediumMinFiles)
          || minBytes !== String(settings.mediumMinBytes)
          || paths !== (settings.protectedPaths || []).join('\n');
      }, [settings, level, minFiles, minBytes, paths]);

      // 客户端预判：把级别往下调（放宽）就先红字提示，不必等保存。
      const pendingLoosen = settings && LEVEL_ORDER.indexOf(level) < LEVEL_ORDER.indexOf(settings.triggerLevel);

      const save = useCallback(async () => {
        setSaving(true);
        setNotice(null);
        try {
          const payload = {
            triggerLevel: level,
            mediumMinFiles: Number(minFiles),
            mediumMinBytes: Number(minBytes),
            protectedPaths: paths.split(/\r?\n/).map((line) => line.trim()).filter(Boolean),
          };
          const response = await fetch(API, {
            method: 'POST',
            headers: { 'content-type': 'application/json', accept: 'application/json' },
            body: JSON.stringify(payload),
          });
          const body = await response.json();
          if (!body.ok) throw new Error(body.error || '保存失败');
          setSettings(body.settings);
          setLevel(body.settings.triggerLevel);
          setMinFiles(String(body.settings.mediumMinFiles));
          setMinBytes(String(body.settings.mediumMinBytes));
          setPaths((body.settings.protectedPaths || []).join('\n'));
          setNotice(body.loosened
            ? { kind: 'warn', text: `已保存，但这是一次**放宽**：${body.from} → ${body.to}。守卫仍在运行，只是敏感区不再弹窗确认。` }
            : { kind: 'ok', text: '已保存并立即生效。' });
        } catch (error) {
          setNotice({ kind: 'err', text: `保存失败：${error.message}` });
        } finally {
          setSaving(false);
        }
      }, [level, minFiles, minBytes, paths]);

      if (loading) return h('div', { style: S.root }, h('p', { style: S.tiny }, '正在读取设置…'));

      return h('div', { style: S.root },
        embedded
          ? h('p', { style: S.lead },
            '只保护 .dsh 与工作区之外：敏感区删除先备份，再弹窗请你确认；.dsh 静默自动备份；工作区完全不干预。',
          )
          : h('div', {},
            h('h1', { style: S.h1 }, '敏感数据守卫'),
            h('p', { style: S.lead },
              '只保护 .dsh 与工作区之外：敏感区删除先备份，再弹窗请你确认；.dsh 静默自动备份；工作区完全不干预。',
            ),
          ),

        h('section', { style: S.card },
          h('p', { style: S.legend }, '提醒级别'),
          ...LEVEL_ORDER.map((value) => h('label', { key: value, style: S.option },
            h('input', {
              type: 'radio',
              name: 'dsh-guard-level',
              checked: level === value,
              onChange: () => { setLevel(value); setNotice(null); },
              style: { marginTop: '3px' },
            }),
            h('span', { style: S.optionText },
              h('span', { style: { fontSize: '12px', fontWeight: 600 } }, LEVEL_LABEL[value]),
              h('span', { style: S.small }, (settings && settings.levelScope && settings.levelScope[value]) || ''),
            ),
          )),
          level === 'medium'
            ? h('div', { style: S.row },
              h('span', { style: S.small }, '阈值：文件数 ≥'),
              h('input', { style: S.num, type: 'number', min: '0', value: minFiles, onChange: (e) => setMinFiles(e.target.value) }),
              h('span', { style: S.small }, '个，或体积 ≥'),
              h('input', { style: S.num, type: 'number', min: '0', value: minBytes, onChange: (e) => setMinBytes(e.target.value) }),
              h('span', { style: S.small }, '字节'),
            )
            : null,
          h('p', { style: S.tiny },
            '范围提醒：这三个级别只影响「敏感区」（.dsh 与当前工作区之外的任何路径）。工作区内的操作永远不备份、不提醒；'
            + '保护目录永远禁止修改，与级别无关。',
          ),
          pendingLoosen
            ? h('div', { style: S.warn },
              `注意：从 ${settings.triggerLevel} 调到 ${level} 是放宽限制。保存后会立刻生效——敏感区的删除将不再弹窗确认。`,
            )
            : null,
        ),

        h('section', { style: S.card },
          h('p', { style: S.legend }, '保护目录（任何级别下都禁止修改，包括本插件自己）'),
          h('textarea', {
            style: S.textarea,
            spellCheck: false,
            value: paths,
            placeholder: '一行一个目录，例如：\nC:\\\\Windows\\\\System32\nD:\\\\Company\\\\Finance\n!D:\\\\Company\\\\Finance\\\\Public   ← 以 ! 开头表示排除',
            onChange: (e) => { setPaths(e.target.value); setNotice(null); },
          }),
          h('p', { style: S.tiny },
            '写法是 .gitignore 风格：含 / 的模式从盘根锚定，不含 / 的匹配任意层级；* 匹配一段、** 跨段、? 单字符；! 开头表示放行；同一路径以后写的规则为准。',
          ),
          (settings && settings.configProtectedPaths && settings.configProtectedPaths.length > 0)
            ? h('div', { style: S.small },
              '配置文件（cordis.patch.yml）里声明的保护目录，属于部署底线，在这里只能看不能删：',
              h('div', {
                style: {
                  fontFamily: 'ui-monospace, SFMono-Regular, Menlo, monospace',
                  fontSize: '11px',
                  lineHeight: 1.7,
                  opacity: 0.8,
                  marginTop: '2px',
                },
              }, settings.configProtectedPaths.join('   ·   ')),
            )
            : null,
        ),

        notice
          ? h('div', {
            style: notice.kind === 'warn' ? S.warn : (notice.kind === 'ok' ? S.ok : S.err),
          }, notice.text)
          : null,

        h('div', { style: S.row },
          h('button', {
            style: dirty ? S.buttonPrimary : S.button,
            disabled: saving || !dirty,
            onClick: save,
          }, saving ? '保存中…' : '保存'),
          h('button', { style: S.button, disabled: saving, onClick: load }, '重新读取'),
          dirty ? h('span', { style: S.tiny }, '有未保存的修改') : null,
        ),

        settings
          ? h('div', { style: S.kv },
            h('span', {}, '.dsh 位置'), h('span', {}, settings.dshHome || '—'),
            h('span', {}, '备份根'), h('span', {}, settings.settingsFile ? settings.settingsFile.replace(/[\\/]data[\\/]settings\.json$/, '') : '—'),
            h('span', {}, '.dsh 备份保留'), h('span', {}, `最新 ${settings.retention.dshCount} 个 / ${settings.retention.dshDays} 天`),
            h('span', {}, '敏感区保留'), h('span', {}, `${settings.retention.sensitiveDays} 天`),
            h('span', {}, '设置文件'), h('span', {}, settings.settingsFile || '—'),
          )
          : null,
      );
    }

    // 插件页（左侧「插件」）里本 bundle 自己的那一块：description 与 rows 之间。
    // view='summary' 只要一行；view='page' 渲染完整表单（去掉大标题，页面本身已有插件名）。
    function BundleConfig({ view } = {}) {
      if (view === 'summary') {
        return h('span', { style: S.tiny },
          '敏感区删除先备份、再弹窗确认；.dsh 静默备份；工作区不干预。',
        );
      }
      return h(Section, { embedded: true });
    }

    return {
      inject: ['slots'],
      apply(ctx) {
        // 设置页：独立的「敏感数据守卫」一节。
        ctx.slots.inject('settings.section', () => ctx.slots.register({
          name: 'settings.section',
          id: 'dsh-sensitive-data-guard',
          order: 25,
          label: '敏感数据守卫',
        }, Section));

        // 插件页：挂在 bundle 自己的页面上，key 就是包名。
        ctx.slots.inject('plugins.bundle.config', () => ctx.slots.register({
          name: 'plugins.bundle.config',
          key: '@local/dsh-sensitive-data-guard',
        }, BundleConfig));
      },
    };
  },
});
