<?php
if (!defined('__TYPECHO_ROOT_DIR__')) exit;

use Typecho\Common;
use Typecho\Widget\Helper\Form;
use Typecho\Widget\Helper\Form\Element\Text;
use Widget\Options;
use Widget\Upload;

/**
 * 可以直接在编辑时粘贴图片自动上传图片至兰空图床(LskyPro)，并返回markdown的图片地址。
 * 该版本是在 isYangs 和 yeying 版本基础之上进行了再次开发，新增图片权限选择、存储策略选择、相册选择等功能，同时修复了其他BUG。
 *
 * @package LskyProUpload pro+
 * @author  老张博客
 * @version 2.0.1
 * @link    https://laozhang.org
 *
 * Changelog v2.0.1 (安全修复):
 *  - [安全] 修复 CSRF Referer 检查可绕过漏洞（空 Referer 不再通过）
 *  - [安全] 修复 unserialize 反序列化漏洞（禁用 allowed_classes）
 *  - [安全] 增加 uploadHandle/deleteHandle/modifyHandle 登录检查
 *  - [安全] 增强 _sanitizeName 文件名过滤（白名单策略）
 *
 * Changelog v1.2.0:
 *  - [安全] 增加登录鉴权，防止未授权上传
 *  - [安全] 增加 CSRF 防护（Referer + X-Requested-With 双重校验）
 *  - [安全] 增加文件真实 MIME 类型校验，防止 MIME 欺骗
 *  - [安全] 启用 SSL 证书验证，防止中间人攻击
 *  - [安全] 使用系统临时目录存放临时文件，避免在 Web 根目录写文件
 *  - [安全] 日志改用 error_log()，不再写入 Web 可访问目录
 *  - [逻辑] modifyHandle 改为先上传成功再删除旧图，避免旧图丢失
 *  - [逻辑] 增加文件大小校验（默认上限 10MB）
 *  - [逻辑] 增加插件配置有效性检查
 *  - [逻辑] 修正 size 字段单位（兰空 API 返回字节，去掉 *1024）
 *  - [逻辑] 修正 attachmentHandle 扩展名截断问题（使用 pathinfo）
 *  - [逻辑] 修正 _deleteImg 返回值（检查 API status 字段）
 *  - [质量] 合并 _curlPost/_curlDelete 为统一 _curlRequest，增加超时
 *  - [质量] IMAGE_EXTENSIONS 去除冗余大写（_getSafeName 已 strtolower）
 *  - [质量] _makeUploadDir 简化为 mkdir 递归模式
 *  - [质量] _getSafeName 拆分为 _sanitizeName + _getExtension，消除引用传参副作用
 */
class LskyProUpload_Plugin implements Typecho_Plugin_Interface
{
    const UPLOAD_DIR   = '/usr/uploads';
    const PLUGIN_NAME  = 'LskyProUpload';
    const VERSION      = '2.0.1';
    const MAX_IMG_SIZE = 10 * 1024 * 1024; // 10 MB，可按需调整

    // 只保留小写扩展名（_getExtension 已做 strtolower）
    const IMAGE_EXTENSIONS = ['gif', 'jpg', 'jpeg', 'png', 'tiff', 'bmp', 'ico', 'psd', 'webp'];

    // 允许的图片 MIME 类型，用于真实文件内容校验
    const IMAGE_MIMES = [
        'image/jpeg', 'image/png', 'image/gif', 'image/webp',
        'image/bmp', 'image/tiff', 'image/x-icon', 'image/vnd.adobe.photoshop',
    ];

    // -------------------------------------------------------------------------
    // 插件生命周期
    // -------------------------------------------------------------------------

    public static function activate()
    {
        Typecho_Plugin::factory('Widget_Upload')->uploadHandle     = ['LskyProUpload_Plugin', 'uploadHandle'];
        Typecho_Plugin::factory('Widget_Upload')->modifyHandle     = ['LskyProUpload_Plugin', 'modifyHandle'];
        Typecho_Plugin::factory('Widget_Upload')->deleteHandle     = ['LskyProUpload_Plugin', 'deleteHandle'];
        Typecho_Plugin::factory('Widget_Upload')->attachmentHandle = ['LskyProUpload_Plugin', 'attachmentHandle'];

        Typecho_Plugin::factory('admin/write-post.php')->bottom = ['LskyProUpload_Plugin', 'injectScript'];
        Typecho_Plugin::factory('admin/write-page.php')->bottom = ['LskyProUpload_Plugin', 'injectScript'];
    }

    public static function deactivate() {}

    public static function config(Form $form)
    {
        // 注册所有字段到 Typecho（用于保存），UI 由下方自定义 HTML 接管
        $desc       = new Text('desc',        null, '',         '', '');
        $api        = new Text('api',         null, '',         '', '');
        $token      = new Text('token',       null, '',         '', '');
        $strategy   = new Text('strategy_id', null, '',         '', '');
        $permission = new Text('permission',  null, '0',        '', '');
        $albumId    = new Text('album_id',     null, '',         '', '');
        $format     = new Text('format',      null, 'markdown', '', '');
        $form->addInput($desc);
        $form->addInput($api);
        $form->addInput($token);
        $form->addInput($strategy);
        $form->addInput($permission);
        $form->addInput($albumId);
        $form->addInput($format);

        // 读取已保存的值，用于自定义 UI 回显
        $opts = null;
        try {
            $opts = Options::alloc()->plugin(self::PLUGIN_NAME);
        } catch (\Typecho\Plugin\Exception $e) {
            // 新安装从未保存过配置，使用空默认值
        }
        $vApi   = htmlspecialchars($opts->api         ?? '', ENT_QUOTES);
        $vToken = htmlspecialchars($opts->token       ?? '', ENT_QUOTES);
        $vStrat = htmlspecialchars($opts->strategy_id ?? '', ENT_QUOTES);
        $vPerm  = htmlspecialchars($opts->permission  ?? '0', ENT_QUOTES);
        $vAlbum = htmlspecialchars($opts->album_id    ?? '', ENT_QUOTES);
        $vFmt   = htmlspecialchars($opts->format      ?? 'markdown', ENT_QUOTES);
        // 预计算 checked 状态（heredoc 中不支持表达式；radio 用 checked，option 用 selected）
        $chkPerm0 = $vPerm === '1' ? 'checked' : '';  // DB=1 → radio value="1"(公开) 选中
        $chkPerm1 = $vPerm === '0' ? 'checked' : '';  // DB=0 → radio value="0"(私有) 选中
        $selFmtMd  = $vFmt === 'markdown' ? 'checked' : '';
        $selFmtUrl = $vFmt === 'url'     ? 'checked' : '';
        $selFmtHtm = $vFmt === 'html'    ? 'checked' : '';
        $selFmtBb  = $vFmt === 'bbcode'  ? 'checked' : '';

        echo <<<HTML
<style>
/* ── Reset & scope ── */
#lsky-panel * { box-sizing: border-box; }
#lsky-panel {
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
    color: #1e293b;
    max-width: 760px;
    margin: 0;
}

/* ── Plugin header banner ── */
.lsky-banner {
    display: flex;
    align-items: center;
    gap: 16px;
    padding: 20px 24px;
    background: linear-gradient(135deg, #1e3a8a 0%, #1d4ed8 50%, #3b82f6 100%);
    border-radius: 14px;
    margin-bottom: 20px;
    position: relative;
    overflow: hidden;
}
.lsky-banner::after {
    content: '';
    position: absolute;
    right: -30px; top: -30px;
    width: 160px; height: 160px;
    border-radius: 50%;
    background: rgba(255,255,255,.06);
}
.lsky-banner::before {
    content: '';
    position: absolute;
    right: 60px; bottom: -40px;
    width: 120px; height: 120px;
    border-radius: 50%;
    background: rgba(255,255,255,.04);
}
.lsky-banner-icon {
    width: 52px; height: 52px;
    background: rgba(255,255,255,.18);
    border-radius: 14px;
    display: flex; align-items: center; justify-content: center;
    font-size: 26px;
    flex-shrink: 0;
    backdrop-filter: blur(4px);
    position: relative; z-index: 1;
}
.lsky-banner-info { position: relative; z-index: 1; }
.lsky-banner-title {
    font-size: 18px;
    font-weight: 700;
    color: #fff;
    margin: 0 0 4px;
    letter-spacing: -.2px;
}
.lsky-banner-desc {
    font-size: 12px;
    color: rgba(255,255,255,.75);
    margin: 0;
    line-height: 1.5;
}
.lsky-banner-ver {
    margin-left: auto;
    font-size: 11px;
    font-weight: 600;
    color: rgba(255,255,255,.6);
    background: rgba(255,255,255,.12);
    padding: 4px 10px;
    border-radius: 20px;
    letter-spacing: .4px;
    position: relative; z-index: 1;
    white-space: nowrap;
}

/* ── Section cards ── */
.lsky-card {
    background: #fff;
    border: 1px solid #e2e8f0;
    border-radius: 12px;
    margin-bottom: 16px;
    overflow: hidden;
    box-shadow: 0 1px 3px rgba(0,0,0,.04);
}
.lsky-card-head {
    display: flex;
    align-items: center;
    gap: 10px;
    padding: 14px 20px;
    background: #f8fafc;
    border-bottom: 1px solid #e2e8f0;
}
.lsky-card-head-icon {
    width: 30px; height: 30px;
    border-radius: 8px;
    display: flex; align-items: center; justify-content: center;
    font-size: 15px;
    flex-shrink: 0;
}
.lsky-card-head-text h3 {
    font-size: 13px;
    font-weight: 600;
    color: #0f172a;
    margin: 0 0 2px;
}
.lsky-card-head-text p {
    font-size: 11px;
    color: #94a3b8;
    margin: 0;
}
.lsky-card-body { padding: 20px; }

/* ── Form fields ── */
.lsky-field { margin-bottom: 16px; }
.lsky-field:last-child { margin-bottom: 0; }
.lsky-field label {
    display: block;
    font-size: 12px;
    font-weight: 600;
    color: #374151;
    margin-bottom: 6px;
    letter-spacing: .2px;
}
.lsky-field label .lsky-required {
    color: #ef4444;
    margin-left: 2px;
}
.lsky-field label .lsky-optional {
    font-size: 10px;
    font-weight: 400;
    color: #94a3b8;
    margin-left: 6px;
    background: #f1f5f9;
    padding: 1px 6px;
    border-radius: 4px;
}
.lsky-input-wrap { position: relative; }
.lsky-input-prefix {
    position: absolute;
    left: 12px; top: 0;
    height: 38px;
    line-height: 38px;
    font-size: 15px;
    pointer-events: none;
}
.lsky-input {
    width: 100%;
    height: 38px;
    line-height: 38px;
    padding: 0 36px 0 38px;
    font-size: 13px;
    color: #1e293b;
    background: #f8fafc;
    border: 1.5px solid #e2e8f0;
    border-radius: 8px;
    outline: none;
    transition: border-color .15s, background .15s, box-shadow .15s;
    font-family: inherit;
    appearance: none;
    -webkit-appearance: none;
    background-image: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='12' height='12' viewBox='0 0 12 12'%3E%3Cpath fill='%2364748b' d='M2 4l4 4 4-4'/%3E%3C/svg%3E");
    background-repeat: no-repeat;
    background-position: right 12px center;
}
.lsky-input:focus {
    border-color: #3b82f6;
    background: #fff;
    box-shadow: 0 0 0 3px rgba(59,130,246,.12);
}
.lsky-input::placeholder { color: #cbd5e1; }
.lsky-field-hint {
    font-size: 11px;
    color: #94a3b8;
    margin-top: 5px;
    line-height: 1.5;
}

/* ── Format cards ── */
.lsky-fmt-grid {
    display: grid;
    grid-template-columns: repeat(4, 1fr);
    gap: 10px;
    margin-bottom: 16px;
}
.lsky-fmt-item { position: relative; }
.lsky-fmt-item input[type="radio"] {
    position: absolute; opacity: 0; width: 0; height: 0; pointer-events: none;
}
.lsky-fmt-item label {
    display: flex;
    flex-direction: column;
    align-items: center;
    gap: 8px;
    padding: 16px 10px 14px;
    border: 2px solid #e2e8f0;
    border-radius: 10px;
    cursor: pointer;
    transition: all .15s;
    background: #fafafa;
    text-align: center;
    user-select: none;
}
.lsky-fmt-item label:hover {
    border-color: #93c5fd;
    background: #f0f9ff;
    transform: translateY(-1px);
    box-shadow: 0 4px 12px rgba(59,130,246,.1);
}
.lsky-fmt-item input:checked + label {
    border-color: #3b82f6;
    background: #eff6ff;
    box-shadow: 0 0 0 3px rgba(59,130,246,.15), 0 4px 12px rgba(59,130,246,.12);
    transform: translateY(-1px);
}
.lsky-fmt-badge {
    font-size: 11px;
    font-weight: 700;
    letter-spacing: .6px;
    padding: 3px 10px;
    border-radius: 6px;
    text-transform: uppercase;
}
.lsky-fmt-badge-md  { background: #dbeafe; color: #1d4ed8; }
.lsky-fmt-badge-url { background: #dcfce7; color: #15803d; }
.lsky-fmt-badge-htm { background: #fef9c3; color: #854d0e; }
.lsky-fmt-badge-bbc { background: #fce7f3; color: #be185d; }
.lsky-fmt-sub {
    font-size: 11px;
    color: #94a3b8;
    line-height: 1.5;
}
.lsky-fmt-item input:checked + label .lsky-fmt-sub { color: #3b82f6; }
.lsky-fmt-tick {
    width: 20px; height: 20px;
    border-radius: 50%;
    background: #3b82f6;
    color: #fff;
    font-size: 11px;
    display: none;
    align-items: center; justify-content: center;
}
.lsky-fmt-item input:checked + label .lsky-fmt-tick { display: flex; }

/* ── Preview box ── */
.lsky-prev-box {
    border: 1px solid #e2e8f0;
    border-radius: 10px;
    overflow: hidden;
    background: #0f172a;
}
.lsky-prev-head {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 10px 16px;
    background: #1e293b;
    border-bottom: 1px solid #334155;
}
.lsky-prev-dots { display: flex; gap: 6px; }
.lsky-prev-dots span {
    width: 10px; height: 10px; border-radius: 50%;
}
.lsky-prev-dots .d1 { background: #ef4444; }
.lsky-prev-dots .d2 { background: #f59e0b; }
.lsky-prev-dots .d3 { background: #22c55e; }
.lsky-prev-label {
    font-size: 11px;
    font-weight: 600;
    color: #64748b;
    letter-spacing: .5px;
    text-transform: uppercase;
}
.lsky-prev-tag {
    font-size: 11px;
    font-weight: 700;
    padding: 2px 10px;
    border-radius: 10px;
}
.lsky-prev-code {
    padding: 16px 20px;
    font-family: "SFMono-Regular", Consolas, "Liberation Mono", Menlo, monospace;
    font-size: 13px;
    line-height: 2;
    word-break: break-all;
    min-height: 56px;
    color: #e2e8f0;
}
/* syntax tokens */
.t-bracket { color: #fb923c; }
.t-alt     { color: #34d399; font-style: italic; }
.t-url     { color: #60a5fa; text-decoration: underline; }
.t-tag     { color: #f87171; }
.t-attr    { color: #c084fc; }
.t-val     { color: #67e8f9; }
.t-bb      { color: #f472b6; font-weight: 600; }

/* ── Status indicator (optional API test hint) ── */
.lsky-status-row {
    display: flex;
    align-items: center;
    gap: 8px;
    margin-top: 12px;
    font-size: 12px;
    color: #64748b;
}
.lsky-status-dot {
    width: 7px; height: 7px;
    border-radius: 50%;
    background: #94a3b8;
    flex-shrink: 0;
}
/* ── Test button ── */
.lsky-btn-test {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    padding: 8px 18px;
    font-size: 13px;
    font-weight: 600;
    color: #3b82f6;
    background: #eff6ff;
    border: 1.5px solid #bfdbfe;
    border-radius: 8px;
    cursor: pointer;
    transition: all .15s;
    font-family: inherit;
}
.lsky-btn-test:hover:not(:disabled) {
    background: #dbeafe;
    border-color: #3b82f6;
    transform: translateY(-1px);
    box-shadow: 0 4px 12px rgba(59,130,246,.15);
}
.lsky-btn-test:disabled {
    opacity: .5;
    cursor: not-allowed;
}
</style>

<div id="lsky-panel">

  <!-- ── Banner ── -->
  <div class="lsky-banner">
    <div class="lsky-banner-icon">🏔️</div>
    <div class="lsky-banner-info">
      <p class="lsky-banner-title">LskyPro Upload</p>
      <p class="lsky-banner-desc">粘贴图片自动上传至兰空图床，支持 Markdown、HTML、BBCode、URL 四种插入格式</p>
    </div>
    <span class="lsky-banner-ver">v2.0.1</span>
  </div>

  <!-- ── Section 1: API 配置 ── -->
  <div class="lsky-card">
    <div class="lsky-card-head">
      <div class="lsky-card-head-icon" style="background:#eff6ff;">🔗</div>
      <div class="lsky-card-head-text">
        <h3>API 配置</h3>
        <p>填写兰空图床的接口地址与鉴权 Token</p>
      </div>
    </div>
    <div class="lsky-card-body">
      <div class="lsky-field">
        <label>API 地址 <span class="lsky-required">*</span></label>
        <div class="lsky-input-wrap">
          <span class="lsky-input-prefix">🌐</span>
          <input class="lsky-input" id="lskyApiInput" type="text"
                 placeholder="https://lsky.pro" value="{$vApi}" autocomplete="off">
        </div>
        <p class="lsky-field-hint">兰空图床的根域名，末尾无需加斜杠</p>
      </div>
      <div class="lsky-field">
        <label>Token <span class="lsky-required">*</span></label>
        <div class="lsky-input-wrap">
          <span class="lsky-input-prefix">🔑</span>
          <input class="lsky-input" id="lskyTokenInput" type="text"
                 placeholder="请输入 API Token" value="{$vToken}" autocomplete="new-password">
        </div>
        <p class="lsky-field-hint">在兰空图床「个人中心 → API」中生成，格式为 <code style="background:#f1f5f9;padding:1px 5px;border-radius:4px;font-size:11px;">Bearer xxxxxxxx</code></p>
      </div>
    </div>
  </div>

  <!-- ── Section 3: 图片权限 ── -->
  <div class="lsky-card">
    <div class="lsky-card-head">
      <div class="lsky-card-head-icon" style="background:#fff7ed;">🔒</div>
      <div class="lsky-card-head-text">
        <h3>图片权限</h3>
        <p>设置图片在兰空图床中的可见性</p>
      </div>
    </div>
    <div class="lsky-card-body">
      <div class="lsky-field" style="margin-bottom:0;">
        <div style="display:flex;gap:12px;margin-top:2px;">
          <label style="display:flex;align-items:center;gap:6px;cursor:pointer;font-size:13px;">
            <input type="radio" name="lsky_perm_ui" id="lperm_0" value="1" {$chkPerm0} style="width:15px;height:15px;cursor:pointer;">
            🌐 公开 <span style="font-size:11px;color:#94a3b8;font-weight:400;">— 所有人可见，可分享</span>
          </label>
          <label style="display:flex;align-items:center;gap:6px;cursor:pointer;font-size:13px;">
            <input type="radio" name="lsky_perm_ui" id="lperm_1" value="0" {$chkPerm1} style="width:15px;height:15px;cursor:pointer;">
            🔐 私有 <span style="font-size:11px;color:#94a3b8;font-weight:400;">— 仅自己可见</span>
          </label>
        </div>
        <p class="lsky-field-hint" style="margin-top:8px;">公开：图片生成公开链接，可分享；私有：仅兰空账号可查看</p>
      </div>
    </div>
  </div>

  <!-- ── Section 4: 存储策略 & 相册 ── -->
  <div class="lsky-card">
    <div class="lsky-card-head">
      <div class="lsky-card-head-icon" style="background:#eff6ff;">📦</div>
      <div class="lsky-card-head-text">
        <h3>存储策略 &amp; 相册</h3>
        <p>指定上传时使用的存储策略和相册（均为可选）</p>
      </div>
    </div>
    <div class="lsky-card-body">
      <!-- 测试连接 -->
      <div class="lsky-field">
        <label>API 连接状态</label>
        <button type="button" id="lskyTestBtn" class="lsky-btn-test">
          🔌 测试连接
        </button>
        <span id="lskyTestMsg" style="font-size:12px;color:#64748b;margin-left:10px;"></span>
      </div>
      <!-- 存储策略 -->
      <div class="lsky-field">
        <label>存储策略 <span class="lsky-optional">可选</span></label>
        <div class="lsky-input-wrap">
          <span class="lsky-input-prefix">🗂️</span>
          <select class="lsky-input" id="lskyStratSelect" style="padding-left:38px;cursor:pointer;">
            <option value="">— 留空（使用默认策略）—</option>
          </select>
        </div>
        <p class="lsky-field-hint">下拉列表自动获取兰空图床的存储策略</p>
      </div>
      <!-- 相册 -->
      <div class="lsky-field">
        <label>上传相册 <span class="lsky-optional">可选</span></label>
        <div class="lsky-input-wrap">
          <span class="lsky-input-prefix">📁</span>
          <select class="lsky-input" id="lskyAlbumSelect" style="padding-left:38px;cursor:pointer;">
            <option value="">— 留空（不上传至相册）—</option>
          </select>
        </div>
        <p class="lsky-field-hint">下拉列表自动获取兰空图床的相册数据</p>
      </div>
    </div>
  </div>

  <!-- ── Section 5: 插入格式 ── -->
  <div class="lsky-card">
    <div class="lsky-card-head">
      <div class="lsky-card-head-icon" style="background:#fdf4ff;">✏️</div>
      <div class="lsky-card-head-text">
        <h3>插入格式</h3>
        <p>粘贴图片上传成功后，插入编辑器的内容格式</p>
      </div>
    </div>
    <div class="lsky-card-body">
      <div class="lsky-fmt-grid">
        <div class="lsky-fmt-item">
          <input type="radio" name="lsky_fmt_ui" id="lfmt_md"  value="markdown">
          <label for="lfmt_md">
            <span class="lsky-fmt-badge lsky-fmt-badge-md">Markdown</span>
            <span class="lsky-fmt-sub">Markdown<br>编辑器通用</span>
            <span class="lsky-fmt-tick">✓</span>
          </label>
        </div>
        <div class="lsky-fmt-item">
          <input type="radio" name="lsky_fmt_ui" id="lfmt_url" value="url">
          <label for="lfmt_url">
            <span class="lsky-fmt-badge lsky-fmt-badge-url">URL</span>
            <span class="lsky-fmt-sub">纯链接<br>自定义使用</span>
            <span class="lsky-fmt-tick">✓</span>
          </label>
        </div>
        <div class="lsky-fmt-item">
          <input type="radio" name="lsky_fmt_ui" id="lfmt_html" value="html">
          <label for="lfmt_html">
            <span class="lsky-fmt-badge lsky-fmt-badge-htm">HTML</span>
            <span class="lsky-fmt-sub">img 标签<br>富文本编辑器</span>
            <span class="lsky-fmt-tick">✓</span>
          </label>
        </div>
        <div class="lsky-fmt-item">
          <input type="radio" name="lsky_fmt_ui" id="lfmt_bb"  value="bbcode">
          <label for="lfmt_bb">
            <span class="lsky-fmt-badge lsky-fmt-badge-bbc">BBCode</span>
            <span class="lsky-fmt-sub">BBCode<br>论坛编辑器</span>
            <span class="lsky-fmt-tick">✓</span>
          </label>
        </div>
      </div>

      <!-- 预览终端 -->
      <div class="lsky-prev-box">
        <div class="lsky-prev-head">
          <div class="lsky-prev-dots">
            <span class="d1"></span><span class="d2"></span><span class="d3"></span>
          </div>
          <span class="lsky-prev-label">Preview</span>
          <span class="lsky-prev-tag" id="lpTag"></span>
        </div>
        <div class="lsky-prev-code" id="lpCode"></div>
      </div>
    </div>
  </div>

</div><!-- #lsky-panel -->

<script>
(function () {
    /* ── 格式预览 ── */
    var INAME = '示例图片';
    var IURL  = 'https://lsky.pro/storage/2024/example.webp';

    var FMTS = {
        markdown: {
            label: 'Markdown', bg: '#1d4ed8', color: '#fff',
            html: function () {
                return '<span class="t-bracket">![</span>'
                     + '<span class="t-alt">' + INAME + '</span>'
                     + '<span class="t-bracket">](</span>'
                     + '<span class="t-url">' + IURL + '</span>'
                     + '<span class="t-bracket">)</span>';
            }
        },
        url: {
            label: 'URL', bg: '#15803d', color: '#fff',
            html: function () {
                return '<span class="t-url">' + IURL + '</span>';
            }
        },
        html: {
            label: 'HTML', bg: '#854d0e', color: '#fff',
            html: function () {
                return '<span class="t-tag">&lt;img</span>'
                     + ' <span class="t-attr">src</span><span class="t-bracket">=</span><span class="t-val">"' + IURL + '"</span>'
                     + '<br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;'
                     + '<span class="t-attr">alt</span><span class="t-bracket">=</span><span class="t-val">"' + INAME + '"</span>'
                     + ' <span class="t-tag">/&gt;</span>';
            }
        },
        bbcode: {
            label: 'BBCode', bg: '#be185d', color: '#fff',
            html: function () {
                return '<span class="t-bb">[img]</span>'
                     + '<span class="t-url">' + IURL + '</span>'
                     + '<span class="t-bb">[/img]</span>';
            }
        }
    };

    function applyFmt(val) {
        var f = FMTS[val] || FMTS.markdown;
        document.getElementById('lpCode').innerHTML = f.html();
        var tag = document.getElementById('lpTag');
        tag.textContent    = f.label;
        tag.style.background = f.bg;
        tag.style.color      = f.color;
        var real = document.querySelector('input[name="format"]');
        if (real) real.value = val;
    }

    /* ── 自定义输入框同步到 Typecho 原生字段 ── */
    function syncField(customId, nativeName) {
        var el = document.getElementById(customId);
        if (!el) return;
        el.addEventListener('input', function () {
            var native = document.querySelector('input[name="' + nativeName + '"]');
            if (native) native.value = this.value;
        });
    }
    syncField('lskyApiInput',   'api');
    syncField('lskyTokenInput', 'token');

    /* ── 加载相册列表 ── */
    function loadAlbums() {
        var apiVal   = lskyGetApi();
        var tokenVal = lskyGetToken();
        if (!apiVal || !tokenVal) return;

        var sel = document.getElementById('lskyAlbumSelect');
        if (!sel) return;
        sel.innerHTML = '<option value="">加载中...</option>';

        var baseUrl = apiVal.replace(/\/$/, '');
        fetch(baseUrl + '/api/v1/albums?page=1', {
            method: 'GET',
            headers: {
                'Accept': 'application/json',
                'Authorization': 'Bearer ' + tokenVal,
            }
        })
        .then(function (r) { return r.json(); })
        .then(function (d) {
            if (!d.status || !d.data || !d.data.data || !d.data.data.length) {
                sel.innerHTML = '<option value="">未找到相册</option>';
                return;
            }
            sel.innerHTML = '<option value="">— 留空（不上传至相册）—</option>';
            d.data.data.forEach(function (a) {
                var opt = document.createElement('option');
                opt.value = String(a.id);
                opt.textContent = a.name + ' (' + a.image_num + '张)';
                sel.appendChild(opt);
            });
            var saved = document.querySelector('input[name="album_id"]');
            if (saved && saved.value) sel.value = saved.value;
        })
        .catch(function () {
            sel.innerHTML = '<option value="">加载失败</option>';
        });
    }

    /* ── 加载存储策略列表 ── */
    function loadStrategies() {
        var apiVal   = lskyGetApi();
        var tokenVal = lskyGetToken();
        if (!apiVal || !tokenVal) return;

        var sel = document.getElementById('lskyStratSelect');
        if (!sel) return;
        sel.innerHTML = '<option value="">加载中...</option>';

        var baseUrl = apiVal.replace(/\/$/, '');
        fetch(baseUrl + '/api/v1/strategies?page=1', {
            method: 'GET',
            headers: {
                'Accept': 'application/json',
                'Authorization': 'Bearer ' + tokenVal,
            }
        })
        .then(function (r) { return r.json(); })
        .then(function (d) {
            // 兼容三种响应结构：
            // 1. {status, data: {strategies: [...]}}  — 兰空 Pro 常见
            // 2. {status, data: [...]}  — 直接数组（未分页）
            // 3. {status, data: {data: [...]}}  — 分页结构
            var items = null;
            if (d.status && d.data) {
                if (Array.isArray(d.data)) {
                    items = d.data; // 格式2：直接数组
                } else if (d.data.data && Array.isArray(d.data.data)) {
                    items = d.data.data; // 格式3：分页结构
                } else if (d.data.strategies && Array.isArray(d.data.strategies)) {
                    items = d.data.strategies; // 格式1：{strategies: [...]}
                }
            }
            if (!items || !items.length) {
                sel.innerHTML = '<option value="">未找到策略</option>';
                return;
            }
            sel.innerHTML = '<option value="">— 留空（使用默认策略）—</option>';
            items.forEach(function (s) {
                var opt = document.createElement('option');
                opt.value = String(s.id);
                opt.textContent = s.name;
                sel.appendChild(opt);
            });
            var saved = document.querySelector('input[name="strategy_id"]');
            if (saved && saved.value) sel.value = saved.value;
        })
        .catch(function () {
            sel.innerHTML = '<option value="">加载失败</option>';
        });
    }

    /* ── 测试连接 ── */
    function testConnection() {
        var apiVal   = lskyGetApi();
        var tokenVal = lskyGetToken();
        var msgEl = document.getElementById('lskyTestMsg');
        var btnEl = document.getElementById('lskyTestBtn');
        if (!apiVal || !tokenVal) {
            msgEl.textContent = '请先填写 API 地址和 Token';
            msgEl.style.color = '#ef4444';
            return;
        }
        msgEl.textContent = '测试中...';
        msgEl.style.color = '#64748b';
        btnEl.disabled = true;

        var baseUrl = apiVal.replace(/\/$/, '');
        fetch(baseUrl + '/api/v1/albums?page=1', {
            method: 'GET',
            headers: {
                'Accept': 'application/json',
                'Authorization': 'Bearer ' + tokenVal,
            }
        })
        .then(function (r) { return r.json(); })
        .then(function (d) {
            btnEl.disabled = false;
            if (d.status) {
                msgEl.textContent = '✅ 连接成功！已获取 ' + (d.data && d.data.data ? d.data.data.length : 0) + ' 个相册';
                msgEl.style.color = '#22c55e';
                loadStrategies();
                loadAlbums();
            } else {
                msgEl.textContent = '❌ 连接失败：' + (d.message || '未知错误');
                msgEl.style.color = '#ef4444';
            }
        })
        .catch(function (e) {
            btnEl.disabled = false;
            msgEl.textContent = '❌ 连接失败：' + e.message;
            msgEl.style.color = '#ef4444';
        });
    }

    /* ── 辅助：获取 API / Token 当前值 ── */
    function lskyGetApi() {
        var el = document.getElementById('lskyApiInput');
        return el ? el.value.trim() : '';
    }
    function lskyGetToken() {
        var el = document.getElementById('lskyTokenInput');
        return el ? el.value.trim() : '';
    }

    /* ── 绑定测试连接按钮 ── */
    var testBtn = document.getElementById('lskyTestBtn');
    if (testBtn) testBtn.addEventListener('click', testConnection);

    /* ── 绑定策略/相册随 API/Token 变化自动刷新 ── */
    function bindReload(el, fn) {
        if (!el) return;
        el.addEventListener('input',  function () { setTimeout(fn, 600); });
        el.addEventListener('change', function () { setTimeout(fn, 600); });
    }
    bindReload(document.getElementById('lskyApiInput'),  loadAlbums);
    bindReload(document.getElementById('lskyTokenInput'), loadAlbums);
    bindReload(document.getElementById('lskyApiInput'),  loadStrategies);
    bindReload(document.getElementById('lskyTokenInput'), loadStrategies);

    /* ── 策略/相册下拉变化时同步到原生字段 ── */
    var stratSel = document.getElementById('lskyStratSelect');
    if (stratSel) stratSel.addEventListener('change', function () {
        var native = document.querySelector('input[name="strategy_id"]');
        if (native) native.value = this.value;
    });
    var albumSel = document.getElementById('lskyAlbumSelect');
    if (albumSel) albumSel.addEventListener('change', function () {
        var native = document.querySelector('input[name="album_id"]');
        if (native) native.value = this.value;
    });

    /* ── 页面加载完成后自动加载策略和相册 ── */
    window.addEventListener('load', function () {
        setTimeout(function () {
            loadStrategies();
            loadAlbums();
        }, 800);
    });

    /* ── 初始化格式卡片（使用预计算的 checked 值） ── */
    var saved = '{$vFmt}';
    var idMap  = { markdown: 'lfmt_md', url: 'lfmt_url', html: 'lfmt_html', bbcode: 'lfmt_bb' };
    var initEl = document.getElementById(idMap[saved] || 'lfmt_md');
    if (initEl) initEl.checked = true;
    applyFmt(saved);

    /* ── 权限单选框同步 ── */
    function syncPerm(val) {
        var native = document.querySelector('input[name="permission"]');
        if (native) native.value = val;
    }
    // 初始化 checked 状态（使用预计算值，同步原生字段）
    document.querySelectorAll('input[name="lsky_perm_ui"]').forEach(function (r) {
        if (r.checked) syncPerm(r.value);
    });
    // 监听变化
    document.querySelectorAll('input[name="lsky_perm_ui"]').forEach(function (r) {
        r.addEventListener('change', function () { syncPerm(this.value); });
    });

    document.querySelectorAll('input[name="lsky_fmt_ui"]').forEach(function (r) {
        r.addEventListener('change', function () { applyFmt(this.value); });
    });

    /* ── 隐藏所有原生 Typecho 表单行 ── */
    window.addEventListener('load', function () {
        ['desc', 'api', 'token', 'strategy_id', 'permission', 'album_id', 'format'].forEach(function (name) {
            var el = document.querySelector('[name="' + name + '"]');
            if (!el) return;
            var row = el.closest('tr') || el.closest('.typecho-option') || el.parentNode;
            if (row) row.style.display = 'none';
        });
    });
})();
</script>
HTML;
    }
    public static function personalConfig(Form $form) {}

    // -------------------------------------------------------------------------
    // 前端脚本注入
    // -------------------------------------------------------------------------

    public static function injectScript()
    {
        echo '<script src="/usr/plugins/LskyProUpload/assets/paste-upload.js?v=' . self::VERSION . '"></script>' . "\n";
    }

    // -------------------------------------------------------------------------
    // 粘贴上传 AJAX 入口
    // -------------------------------------------------------------------------

    /**
     * 处理前端粘贴上传的 AJAX 请求
     */
    public static function pasteUploadHandle()
    {
        // 1. 登录鉴权
        $user = \Widget\User::alloc();
        if (!$user->hasLogin()) {
            self::jsonResponse(false, '未登录，无权上传');
        }

        // 2. CSRF 防护：双重校验
        //    a) X-Requested-With（JS 端设置，普通表单无法伪造）
        if (($_SERVER['HTTP_X_REQUESTED_WITH'] ?? '') !== 'XMLHttpRequest') {
            self::jsonResponse(false, '非法请求');
        }
        //    b) Referer 来源校验（空 Referer 也拒绝，防止 data: URL 等绕过）
        $referer = $_SERVER['HTTP_REFERER'] ?? '';
        $siteUrl = rtrim(Options::alloc()->siteUrl, '/');
        if (empty($referer) || strpos($referer, $siteUrl) !== 0) {
            self::jsonResponse(false, '非法请求来源');
        }

        // 3. 配置有效性检查
        if ($cfgErr = self::_validateConfig()) {
            self::jsonResponse(false, $cfgErr);
        }

        // 4. 文件存在性检查
        if (empty($_FILES['file']) || $_FILES['file']['error'] !== UPLOAD_ERR_OK) {
            self::jsonResponse(false, '未接收到文件或上传出错');
        }

        $file = $_FILES['file'];

        // 5. 文件大小校验（前端已拦截，后端兜底）
        if ($file['size'] > self::MAX_IMG_SIZE) {
            self::jsonResponse(false, '图片大小不能超过 ' . (self::MAX_IMG_SIZE / 1024 / 1024) . 'MB');
        }

        // 6. 扩展名校验
        $name = $file['name'];
        $ext  = self::_getExtension($name);
        if (!self::_isImage($ext)) {
            self::jsonResponse(false, '仅支持上传图片格式');
        }

        // 7. 真实 MIME 校验，防止 MIME 欺骗（如把 PHP 改名为 .jpg）
        if (!self::_isRealImage($file['tmp_name'])) {
            self::jsonResponse(false, '文件内容不是合法图片');
        }

        // 8. 处理自定义文件名
        $customName = !empty($_POST['name']) ? trim($_POST['name']) : null;
        if ($customName) {
            $customName   = pathinfo($customName, PATHINFO_FILENAME); // 去掉可能带的扩展名
            $file['name'] = self::_sanitizeName($customName) . '.' . $ext;
        }

        // 9. 上传到图床
        $result = self::_uploadImg($file, $ext);
        if (!$result) {
            self::jsonResponse(false, '图片上传失败，请检查图床配置');
        }

        $imageName = $customName ?: pathinfo($result['name'], PATHINFO_FILENAME);
        $content   = self::_formatContent($imageName, $result['path']);

        self::jsonResponse(true, '上传成功', [
            'content' => $content,
            'url'     => $result['path'],
            'name'    => $imageName,
        ]);
    }

    // -------------------------------------------------------------------------
    // Typecho 上传 Hook 实现
    // -------------------------------------------------------------------------

    public static function uploadHandle($file)
    {
        if (empty($file['name'])) {
            return false;
        }

        // 安全检查：确保用户已登录
        $user = \Widget\User::alloc();
        if (!$user->hasLogin()) {
            return false;
        }

        $name = $file['name'];
        $ext  = self::_getExtension($name);
        $file['name'] = self::_sanitizeName($name) . '.' . $ext;

        if (!Upload::checkFileType($ext) || Common::isAppEngine()) {
            return false;
        }

        if (self::_isImage($ext)) {
            return self::_uploadImg($file, $ext);
        }

        return self::_uploadOtherFile($file, $ext);
    }

    public static function deleteHandle(array $content): bool
    {
        // 安全检查：确保用户已登录
        $user = \Widget\User::alloc();
        if (!$user->hasLogin()) {
            return false;
        }

        $ext = $content['attachment']->type;

        if (self::_isImage($ext)) {
            return self::_deleteImg($content);
        }

        $path = $content['attachment']->path;
        // 修复：删除前先检查文件是否存在，避免产生 PHP Warning
        return file_exists($path) && unlink($path);
    }

    public static function modifyHandle($content, $file)
    {
        if (empty($file['name'])) {
            return false;
        }

        // 安全检查：确保用户已登录
        $user = \Widget\User::alloc();
        if (!$user->hasLogin()) {
            return false;
        }

        $name = $file['name'];
        $ext  = self::_getExtension($name);

        if ($content['attachment']->type !== $ext || Common::isAppEngine()) {
            return false;
        }

        if (!self::_getUploadFile($file)) {
            return false;
        }

        if (self::_isImage($ext)) {
            // 修复：先上传新图，成功后再删除旧图，避免上传失败导致旧图永久丢失
            $newResult = self::_uploadImg($file, $ext);
            if ($newResult) {
                self::_deleteImg($content);
            }
            return $newResult;
        }

        return self::_uploadOtherFile($file, $ext);
    }

    public static function attachmentHandle(array $content): string
    {
        // 修复：使用 pathinfo 获取扩展名，避免 substr 截断 webp/tiff/jpeg 等
        // 修复：使用 allowed_classes=false 防止 PHP 对象注入攻击
        // 修复：unserialize 失败时返回 false，需做类型校验避免 PHP Warning
        $arr = @unserialize($content['text'], ['allowed_classes' => false]);
        if (!is_array($arr) || empty($arr['path'])) {
            return $content['attachment']->path ?? '';
        }

        $ext = strtolower(pathinfo($arr['path'], PATHINFO_EXTENSION));

        if (self::_isImage($ext)) {
            return $content['attachment']->path ?? '';
        }

        $ret = explode(self::UPLOAD_DIR, $arr['path']);
        return Common::url(self::UPLOAD_DIR . ($ret[1] ?? ''), Options::alloc()->siteUrl);
    }

    // -------------------------------------------------------------------------
    // 私有辅助方法
    // -------------------------------------------------------------------------

    /**
     * 根据后台配置的格式，将图片名和 URL 格式化为对应的插入文本
     */
    private static function _formatContent(string $name, string $url): string
    {
        $format = Options::alloc()->plugin(self::PLUGIN_NAME)->format ?? 'markdown';
        switch ($format) {
            case 'url':
                return $url;
            case 'html':
                return '<img src="' . htmlspecialchars($url, ENT_QUOTES) . '" alt="' . htmlspecialchars($name, ENT_QUOTES) . '" />';
            case 'bbcode':
                return '[img]' . $url . '[/img]';
            case 'markdown':
            default:
                return '![' . $name . '](' . $url . ')';
        }
    }

    /**
     * 校验插件配置是否完整，返回错误信息或 null
     */
    private static function _validateConfig(): ?string
    {
        $options = Options::alloc()->plugin(self::PLUGIN_NAME);
        if (empty($options->api)) {
            return '请先在插件设置中填写 API 地址';
        }
        if (empty($options->token)) {
            return '请先在插件设置中填写 Token';
        }
        return null;
    }

    /**
     * 校验文件真实 MIME 类型（防止 MIME 欺骗）
     */
    private static function _isRealImage(string $tmpPath): bool
    {
        if (!function_exists('finfo_open')) {
            // 若 finfo 不可用，降级为 getimagesize 校验
            return @getimagesize($tmpPath) !== false;
        }
        $finfo = new finfo(FILEINFO_MIME_TYPE);
        $mime  = $finfo->file($tmpPath);
        return in_array($mime, self::IMAGE_MIMES, true);
    }

    /**
     * 净化文件名（去除危险字符，返回无扩展名的安全文件名）
     */
    private static function _sanitizeName(string $name): string
    {
        // 只保留安全字符：字母、数字、下划线、连字符、中文
        $name = preg_replace('/[^a-zA-Z0-9_\-\x{4e00}-\x{9fa5}]/u', '', $name);
        $name = pathinfo($name, PATHINFO_FILENAME);
        return $name ?: 'image';
    }

    /**
     * 提取并返回小写扩展名
     */
    private static function _getExtension(string $name): string
    {
        $name = str_replace('\\', '/', $name);
        return strtolower(pathinfo($name, PATHINFO_EXTENSION));
    }

    private static function _isImage(string $ext): bool
    {
        return in_array($ext, self::IMAGE_EXTENSIONS, true);
    }

    private static function _getUploadFile(array $file): string
    {
        return $file['tmp_name'] ?? ($file['bytes'] ?? ($file['bits'] ?? ''));
    }

    private static function _getUploadDir(string $ext = ''): string
    {
        if (self::_isImage($ext)) {
            $url = parse_url(Options::alloc()->siteUrl);
            $dir = str_replace('.', '_', $url['host'] ?? 'local');
            return '/' . $dir . self::UPLOAD_DIR;
        }
        if (defined('__TYPECHO_UPLOAD_DIR__')) {
            return __TYPECHO_UPLOAD_DIR__;
        }
        return Common::url(self::UPLOAD_DIR, __TYPECHO_ROOT_DIR__);
    }

    /**
     * 简化版目录创建（利用 mkdir 的 recursive 参数）
     */
    private static function _makeUploadDir(string $path): bool
    {
        return is_dir($path) || mkdir($path, 0755, true);
    }

    private static function _uploadOtherFile(array $file, string $ext)
    {
        $dir = self::_getUploadDir($ext) . '/' . date('Y') . '/' . date('m');

        if (!self::_makeUploadDir($dir)) {
            return false;
        }

        $path = sprintf('%s/%u.%s', $dir, crc32(uniqid()), $ext);

        if (!isset($file['tmp_name']) || !@move_uploaded_file($file['tmp_name'], $path)) {
            return false;
        }

        return [
            'name' => $file['name'],
            'path' => $path,
            'size' => $file['size'] ?? filesize($path),
            'type' => $ext,
            'mime' => Common::mimeContentType($path),
        ];
    }

    private static function _uploadImg(array $file, string $ext)
    {
        $options    = Options::alloc()->plugin(self::PLUGIN_NAME);
        $api        = rtrim($options->api, '/') . '/api/v1/upload';
        $token      = 'Bearer ' . $options->token;
        $strategyId = $options->strategy_id ?? '';

        $tmp = self::_getUploadFile($file);
        if (empty($tmp)) {
            return false;
        }

        // 使用系统临时目录，避免在 Web 可访问目录创建文件
        // tempnam() 会创建一个占位文件（无扩展名），我们只需要它生成的唯一路径，
        // 再附加扩展名作为实际文件路径，并立即删除占位文件，避免临时文件泄露
        $tmpBase = tempnam(sys_get_temp_dir(), 'lsky_');
        $img     = $tmpBase . '.' . $ext;
        @unlink($tmpBase); // 删除 tempnam 创建的占位文件

        if (!rename($tmp, $img)) {
            return false;
        }

        // 获取 MIME 类型（与 _isRealImage 保持一致，兼容未安装 fileinfo 扩展的环境）
        if (function_exists('finfo_open')) {
            $mime = (new finfo(FILEINFO_MIME_TYPE))->file($img);
        } else {
            $imageInfo = @getimagesize($img);
            $mime      = $imageInfo['mime'] ?? 'application/octet-stream';
        }
        $params = ['file' => new CURLFile($img, $mime, $file['name'])];
        if (!empty($strategyId)) {
            $params['strategy_id'] = $strategyId;
        }
        $perm = $options->permission ?? '1';
        if ($perm !== '') {
            $permInt = intval($perm);
            $params['permission'] = $permInt;
            $params['is_public'] = $permInt;
        }
        $albumId = $options->album_id ?? '';
        if ($albumId !== '') {
            $params['album_id'] = $albumId;
        }

        $res = self::_curlRequest('POST', $api, $params, $token);

        // 确保临时文件被清理
        if (file_exists($img)) {
            unlink($img);
        }

        if (!$res) {
            return false;
        }

        $json = json_decode($res, true);

        // 修复：用 empty() 替代 === false，同时捕获 status 为 0/null/false 的情况
        if (empty($json) || empty($json['status'])) {
            error_log('[LskyProUpload] 上传失败: ' . json_encode($json, JSON_UNESCAPED_UNICODE));
            return false;
        }

        $data = $json['data'];
        return [
            'img_key'     => $data['key'],
            'img_id'      => $data['md5'],
            'name'        => $data['origin_name'],
            'path'        => $data['links']['url'],
            'size'        => $data['size'],       // 修复：兰空 API 返回单位为字节，无需 *1024
            'type'        => $data['extension'],
            'mime'        => $data['mimetype'],
            'description' => $data['mimetype'],
        ];
    }

    private static function _deleteImg(array $content): bool
    {
        $options = Options::alloc()->plugin(self::PLUGIN_NAME);
        $api     = rtrim($options->api, '/') . '/api/v1/images';
        $token   = 'Bearer ' . $options->token;
        $id      = $content['attachment']->img_key ?? '';

        if (empty($id)) {
            return false;
        }

        $res  = self::_curlRequest('DELETE', $api . '/' . $id, ['key' => $id], $token);
        $json = json_decode($res, true);

        return is_array($json) && ($json['status'] === true);
    }

    /**
     * 统一 cURL 请求方法（合并原 _curlPost / _curlDelete，增加超时 & SSL 校验）
     *
     * @param string $method  HTTP 方法，如 POST / DELETE
     * @param string $api     请求 URL
     * @param array  $post    请求体数据
     * @param string $token   Bearer Token
     * @return string|false   响应内容，失败返回 false
     */
    private static function _curlRequest(string $method, string $api, array $post, string $token)
    {
        $headers = [
            'Content-Type: multipart/form-data',
            'Accept: application/json',
            'Authorization: ' . $token,
        ];

        $ch = curl_init();
        curl_setopt_array($ch, [
            CURLOPT_URL            => $api,
            // 修复：启用 SSL 证书验证，防止中间人攻击
            CURLOPT_SSL_VERIFYPEER => true,
            CURLOPT_SSL_VERIFYHOST => 2,
            CURLOPT_FOLLOWLOCATION => false,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_HTTPHEADER     => $headers,
            CURLOPT_CUSTOMREQUEST  => strtoupper($method),
            // 修复：仅 POST 请求才设置 CURLOPT_POST，避免与 CURLOPT_CUSTOMREQUEST=DELETE 冲突
            CURLOPT_POST           => strtoupper($method) === 'POST',
            CURLOPT_POSTFIELDS     => $post,
            CURLOPT_CONNECTTIMEOUT => 10,
            CURLOPT_TIMEOUT        => 60,
            CURLOPT_USERAGENT      => 'LskyProUpload/' . self::VERSION,
        ]);

        $res      = curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);

        if (curl_errno($ch)) {
            error_log('[LskyProUpload] cURL 错误 (' . $method . ' ' . $api . '): ' . curl_error($ch));
            curl_close($ch);
            return false;
        }

        curl_close($ch);

        // 修复：非 2xx 响应视为失败
        if ($httpCode < 200 || $httpCode >= 300) {
            error_log('[LskyProUpload] HTTP 错误 ' . $httpCode . ' (' . $method . ' ' . $api . ')');
            return false;
        }

        return $res;
    }

    /**
     * 输出 JSON 响应并终止脚本
     */
    private static function jsonResponse(bool $status, string $message, array $data = [])
    {
        header('Content-Type: application/json; charset=utf-8');
        echo json_encode([
            'status'  => $status,
            'message' => $message,
            'data'    => $data,
        ], JSON_UNESCAPED_UNICODE);
        exit;
    }
}

// -------------------------------------------------------------------------
// AJAX 粘贴上传入口（文件末尾触发，避免污染类作用域）
// -------------------------------------------------------------------------
if (
    isset($_GET['action'])
    && $_GET['action'] === 'lsky_paste_upload'
    && $_SERVER['REQUEST_METHOD'] === 'POST'
) {
    while (ob_get_level()) {
        ob_end_clean();
    }
    LskyProUpload_Plugin::pasteUploadHandle();
}
