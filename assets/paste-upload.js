/**
 * LskyProUpload 粘贴图片上传功能
 * 在 Typecho 编辑器中，粘贴图片时直接上传到兰空图床
 *
 * @version 1.2.0
 *
 * Changelog v1.2.0:
 *  - [安全] showInputDialog 改用 DOM API 构建，消除 XSS 风险
 *  - [安全] 增加 X-Requested-With 请求头（配合后端 CSRF 防护）
 *  - [逻辑] 增加前端文件大小校验（10MB）
 *  - [逻辑] insertMarkdown 改用现代 Range API，替代废弃的 document.execCommand
 *  - [逻辑] handlePaste 增加并发锁，防止同时触发多个上传
 *  - [体验] Dialog 增加键盘焦点陷阱（Tab 循环 + Esc 关闭）
 *  - [体验] showToast 补充 @keyframes 动画定义
 *  - [体验] init 增加最大重试次数（10 次），避免无限循环
 *  - [体验] 初始化成功/失败均输出 console 日志，方便调试
 */

// 防止脚本重复加载
if (window.__LskyProUploadLoaded) {
  throw new Error('[LskyProUpload] 脚本已加载，请勿重复引入');
}
window.__LskyProUploadLoaded = true;

(function () {
  'use strict';

  // ---------------------------------------------------------------------------
  // 常量
  // ---------------------------------------------------------------------------
  const MAX_FILE_SIZE = 10 * 1024 * 1024; // 10 MB
  const MAX_RETRIES   = 10;               // init 最大重试次数

  // ---------------------------------------------------------------------------
  // 全局状态
  // ---------------------------------------------------------------------------
  let _retryCount  = 0;
  let _isUploading = false; // 并发锁，防止同时上传多张图片

  // ---------------------------------------------------------------------------
  // 注入全局动画样式（仅注入一次）
  // ---------------------------------------------------------------------------
  (function injectStyles() {
    if (document.getElementById('lsky-styles')) return;
    const style = document.createElement('style');
    style.id = 'lsky-styles';
    style.textContent = `
      @keyframes lskySlideIn {
        from { opacity: 0; transform: translateX(20px); }
        to   { opacity: 1; transform: translateX(0);    }
      }
    `;
    document.head.appendChild(style);
  })();

  // ---------------------------------------------------------------------------
  // 工具函数
  // ---------------------------------------------------------------------------

  /** 获取编辑器元素 */
  const getEditor = () => {
    return (
      document.querySelector('.cm-content[contenteditable]') ||  // CodeMirror
      document.querySelector('.joe_owo__target') ||               // Joe 主题
      document.querySelector('textarea[name="text"]') ||          // Typecho 后台
      (() => {                                                     // 最大 textarea 兜底
        const tas = [...document.querySelectorAll('textarea')];
        return tas.length
          ? tas.reduce((a, b) => (b.offsetHeight > a.offsetHeight ? b : a))
          : null;
      })()
    );
  };

  /** 判断是否为图片文件 */
  const isImage = (file) => {
    const allowedTypes = [
      'image/jpeg', 'image/png', 'image/gif',
      'image/webp', 'image/bmp', 'image/tiff',
    ];
    return allowedTypes.includes(file.type) ||
      /\.(jpg|jpeg|png|gif|webp|bmp|tiff)$/i.test(file.name);
  };

  /** 生成默认图片名（去掉扩展名） */
  const generateDefaultName = (filename) => {
    const idx = filename.lastIndexOf('.');
    return idx > 0 ? filename.substring(0, idx) : filename;
  };

  // ---------------------------------------------------------------------------
  // UI 组件
  // ---------------------------------------------------------------------------

  /**
   * 输入对话框
   * 修复：全部使用 DOM API 构建，避免 innerHTML 的 XSS 风险
   * 修复：增加键盘焦点陷阱（Tab 循环 + Esc 关闭）
   */
  const showInputDialog = (defaultName) => {
    return new Promise((resolve) => {
      /* ---- 遮罩 ---- */
      const overlay = document.createElement('div');
      Object.assign(overlay.style, {
        position: 'fixed', inset: '0',
        background: 'rgba(0,0,0,0.5)',
        display: 'flex', justifyContent: 'center', alignItems: 'center',
        zIndex: '99999',
      });

      /* ---- 对话框 ---- */
      const dialog = document.createElement('div');
      Object.assign(dialog.style, {
        background: '#fff', padding: '30px', borderRadius: '8px',
        boxShadow: '0 4px 16px rgba(0,0,0,0.2)',
        maxWidth: '400px', width: '90%',
        fontFamily: '-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif',
      });

      /* ---- 标题 ---- */
      const title = document.createElement('h3');
      Object.assign(title.style, { margin: '0 0 6px 0', fontSize: '18px', color: '#333' });
      title.textContent = '请输入图片名称';

      /* ---- 提示 ---- */
      const hint = document.createElement('p');
      Object.assign(hint.style, { margin: '0 0 18px 0', fontSize: '12px', color: '#999' });
      hint.textContent = '不包含扩展名，直接回车使用默认名称';

      /* ---- 输入框 ---- */
      const input = document.createElement('input');
      input.type = 'text';
      input.value = defaultName; // 直接赋值，避免拼到 innerHTML
      Object.assign(input.style, {
        width: '100%', padding: '10px', border: '1px solid #ddd',
        borderRadius: '4px', fontSize: '14px',
        boxSizing: 'border-box', marginBottom: '15px',
      });

      /* ---- 按钮行 ---- */
      const btnRow = document.createElement('div');
      Object.assign(btnRow.style, { display: 'flex', gap: '10px', justifyContent: 'flex-end' });

      const cancelBtn = document.createElement('button');
      Object.assign(cancelBtn.style, {
        padding: '8px 16px', border: '1px solid #ddd',
        background: '#f5f5f5', borderRadius: '4px',
        cursor: 'pointer', fontSize: '14px',
      });
      cancelBtn.textContent = '取消';

      const confirmBtn = document.createElement('button');
      Object.assign(confirmBtn.style, {
        padding: '8px 16px', border: 'none',
        background: '#1890ff', color: '#fff',
        borderRadius: '4px', cursor: 'pointer', fontSize: '14px',
      });
      confirmBtn.textContent = '确认';

      btnRow.append(cancelBtn, confirmBtn);
      dialog.append(title, hint, input, btnRow);
      overlay.appendChild(dialog);
      document.body.appendChild(overlay);

      /* ---- 事件处理 ---- */
      const cleanup = () => document.body.removeChild(overlay);
      const confirm = () => {
        const name = input.value.trim() || defaultName;
        cleanup();
        resolve(name);
      };
      const cancel = () => { cleanup(); resolve(null); };

      confirmBtn.addEventListener('click', confirm);
      cancelBtn.addEventListener('click', cancel);
      input.addEventListener('keydown', (e) => {
        if (e.key === 'Enter') { e.preventDefault(); confirm(); }
      });

      /* ---- 键盘焦点陷阱（Tab 循环 + Esc 关闭） ---- */
      const focusable = [input, cancelBtn, confirmBtn];
      overlay.addEventListener('keydown', (e) => {
        if (e.key === 'Escape') { cancel(); return; }
        if (e.key === 'Tab') {
          e.preventDefault();
          const idx  = focusable.indexOf(document.activeElement);
          const next = e.shiftKey
            ? focusable[(idx - 1 + focusable.length) % focusable.length]
            : focusable[(idx + 1) % focusable.length];
          next.focus();
        }
      });

      input.focus();
      input.select();
    });
  };

  /** 进度条 */
  const showProgress = () => {
    const wrap = document.createElement('div');
    Object.assign(wrap.style, {
      position: 'fixed', top: '50%', left: '50%',
      transform: 'translate(-50%,-50%)',
      background: '#fff', padding: '30px', borderRadius: '8px',
      boxShadow: '0 2px 20px rgba(0,0,0,0.3)',
      zIndex: '999999', minWidth: '300px', textAlign: 'center',
      fontFamily: '-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif',
    });

    const label = document.createElement('p');
    Object.assign(label.style, { margin: '0 0 15px', color: '#333', fontSize: '14px', fontWeight: 'bold' });
    label.textContent = '正在上传图片...';

    const track = document.createElement('div');
    Object.assign(track.style, {
      width: '100%', height: '8px', background: '#f0f0f0',
      borderRadius: '4px', overflow: 'hidden', marginBottom: '10px',
    });

    const bar = document.createElement('div');
    Object.assign(bar.style, {
      height: '100%', width: '0%',
      background: 'linear-gradient(90deg,#1890ff,#52c41a)',
      transition: 'width .3s ease',
    });

    const pct = document.createElement('p');
    Object.assign(pct.style, { margin: '0', color: '#999', fontSize: '12px' });
    pct.textContent = '0%';

    track.appendChild(bar);
    wrap.append(label, track, pct);
    document.body.appendChild(wrap);

    return {
      update: (percent) => {
        bar.style.width = percent + '%';
        pct.textContent = percent + '%';
      },
      close: () => {
        if (document.body.contains(wrap)) document.body.removeChild(wrap);
      },
    };
  };

  /** Toast 提示 */
  const showToast = (message, type = 'success') => {
    const toast = document.createElement('div');
    Object.assign(toast.style, {
      position: 'fixed', top: '50px', right: '20px',
      background: type === 'success' ? '#52c41a' : '#f5222d',
      color: '#fff', padding: '12px 20px', borderRadius: '4px',
      fontSize: '14px', zIndex: '999999',
      fontFamily: '-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif',
      boxShadow: '0 4px 12px rgba(0,0,0,0.15)',
      animation: 'lskySlideIn .3s ease',  // 已在页面顶部注入 keyframes
    });
    toast.textContent = message;
    document.body.appendChild(toast);
    setTimeout(() => {
      if (document.body.contains(toast)) document.body.removeChild(toast);
    }, 3000);
  };

  // ---------------------------------------------------------------------------
  // 核心逻辑
  // ---------------------------------------------------------------------------

  /**
   * 将 Markdown 插入编辑器光标处
   * 修复：ContentEditable 使用现代 Range API，替代废弃的 document.execCommand
   */
  const insertMarkdown = (editor, markdown, savedRange) => {
    if (editor.tagName === 'TEXTAREA') {
      const start = editor.selectionStart;
      const end   = editor.selectionEnd;
      editor.value = editor.value.slice(0, start) + markdown + editor.value.slice(end);
      editor.focus();
      editor.setSelectionRange(start + markdown.length, start + markdown.length);
      editor.dispatchEvent(new Event('input', { bubbles: true }));
      return;
    }

    // ContentEditable：恢复粘贴前保存的光标
    editor.focus();
    let range = null;

    if (savedRange) {
      try {
        const sel = window.getSelection();
        sel.removeAllRanges();
        sel.addRange(savedRange);
        range = savedRange;
      } catch (_) { /* 恢复失败，继续 */ }
    }

    if (!range) {
      const sel = window.getSelection();
      range = sel.rangeCount > 0 ? sel.getRangeAt(0) : null;
    }

    if (range) {
      // 使用标准 Range API 插入文本节点
      range.deleteContents();
      const node = document.createTextNode(markdown);
      range.insertNode(node);
      range.setStartAfter(node);
      range.collapse(true);
      const sel = window.getSelection();
      sel.removeAllRanges();
      sel.addRange(range);
    } else {
      // 兜底：追加到末尾
      editor.textContent += markdown;
    }

    editor.dispatchEvent(new Event('input',  { bubbles: true }));
    editor.dispatchEvent(new Event('change', { bubbles: true }));
  };

  /**
   * 上传图片并插入 Markdown
   */
  const uploadImage = async (file, imageName, savedRange) => {
    const editor = getEditor();
    if (!editor) {
      console.error('[LskyProUpload] 找不到编辑器元素');
      showToast('编辑器加载失败', 'error');
      return;
    }

    // 提前记录 textarea 光标（对话框弹出后光标会丢失）
    const cursorPos = editor.tagName === 'TEXTAREA' ? editor.selectionStart : 0;

    const formData = new FormData();
    formData.append('file', file);
    formData.append('name', imageName);

    const progress = showProgress();

    try {
      const uploadUrl = new URL(window.location.href);
      uploadUrl.search = '';
      uploadUrl.searchParams.set('action', 'lsky_paste_upload');

      const xhr = new XMLHttpRequest();

      xhr.upload.addEventListener('progress', (e) => {
        if (e.lengthComputable) {
          progress.update(Math.round((e.loaded / e.total) * 100));
        }
      });

      const response = await new Promise((resolve, reject) => {
        xhr.onload = () => {
          if (xhr.status === 200) {
            try   { resolve(JSON.parse(xhr.responseText)); }
            catch { reject(new Error('响应格式错误: ' + xhr.responseText)); }
          } else {
            reject(new Error('HTTP ' + xhr.status));
          }
        };
        xhr.onerror = () => reject(new Error('网络错误'));
        xhr.onabort = () => reject(new Error('请求被中止'));

        xhr.open('POST', uploadUrl.toString(), true);
        // 增加 X-Requested-With 头，配合后端 CSRF 校验
        xhr.setRequestHeader('X-Requested-With', 'XMLHttpRequest');
        xhr.send(formData);
      });

      progress.close();

      if (response.status) {
        if (editor.tagName === 'TEXTAREA') {
          // Textarea：用提前记录的光标位置插入
          const text = editor.value;
          editor.value = text.slice(0, cursorPos) + response.data.content + text.slice(cursorPos);
          editor.focus();
          editor.setSelectionRange(
            cursorPos + response.data.content.length,
            cursorPos + response.data.content.length
          );
          editor.dispatchEvent(new Event('input', { bubbles: true }));
        } else {
          insertMarkdown(editor, response.data.content, savedRange);
        }
        showToast('图片上传成功', 'success');
      } else {
        console.error('[LskyProUpload] 上传失败:', response.message);
        showToast(response.message || '上传失败', 'error');
      }
    } catch (error) {
      progress.close();
      console.error('[LskyProUpload] 上传出错:', error);
      showToast(error.message || '上传出错', 'error');
    }
  };

  /**
   * 处理粘贴事件
   * 修复：增加并发锁，防止同时触发多个上传导致对话框叠加
   */
  const handlePaste = async (e) => {
    const items = e.clipboardData?.items;
    if (!items) return;

    for (const item of items) {
      if (item.kind !== 'file') continue;

      const file = item.getAsFile();
      if (!file || !isImage(file)) continue;

      e.preventDefault();
      e.stopImmediatePropagation();

      // 并发锁：上传进行中时给出提示
      if (_isUploading) {
        showToast('请等待当前图片上传完成', 'error');
        return;
      }

      // 前端文件大小校验
      if (file.size > MAX_FILE_SIZE) {
        showToast(`图片大小不能超过 ${MAX_FILE_SIZE / 1024 / 1024}MB`, 'error');
        return;
      }

      // 保存光标位置（对话框会使 contenteditable 失焦）
      let savedRange = null;
      try {
        const sel = window.getSelection();
        if (sel.rangeCount > 0) savedRange = sel.getRangeAt(0).cloneRange();
      } catch (_) { /* 忽略 */ }

      _isUploading = true; // 在弹出对话框之前就设为 true，阻止 Typecho 的上传流程
      const imageName = await showInputDialog(generateDefaultName(file.name));
      if (!imageName) {
        _isUploading = false; // 用户取消也要重置
        return;
      }

      try {
        await uploadImage(file, imageName, savedRange);
      } finally {
        _isUploading = false;
      }

      return; // 每次只处理第一张图片
    }
  };

  /**
   * 初始化：绑定粘贴事件到编辑器
   * 修复：增加最大重试次数，避免 setInterval 泄漏
   */
  const init = () => {
    if (_retryCount >= MAX_RETRIES) {
      console.warn('[LskyProUpload] 超过最大重试次数，未能找到编辑器，插件未能初始化');
      return;
    }

    const editor = getEditor();
    if (!editor) {
      _retryCount++;
      console.log(`[LskyProUpload] 等待编辑器加载... (${_retryCount}/${MAX_RETRIES})`);
      setTimeout(init, 1000);
      return;
    }

    editor.addEventListener('paste', handlePaste, true);
    console.log('[LskyProUpload] 初始化成功，已绑定到编辑器:', editor.tagName,
      editor.className ? '.' + editor.className.trim().split(/\s+/).join('.') : '');

    // 拦截 Typecho 默认的上传流程，防止双重上传
    // 思路：保存原函数，仅在 paste-upload.js 正在处理对话框时才拦截，
    // 处理完毕后立即恢复原函数，避免长时间覆盖影响其他流程
    if (typeof Typecho !== 'undefined' && Typecho.uploadFile) {
      window._origUploadFile = Typecho.uploadFile;
      // 覆盖为检查 _isUploading 的版本：有上传在进行则拦截（说明是 paste.js 触发的手滑）
      Typecho.uploadFile = function(file) {
        if (_isUploading) {
          console.log('[LskyProUpload] 已拦截 Typecho 默认上传，图片将由兰空图床处理');
          return;
        }
        // 未在上传，走默认流程
        window._origUploadFile.call(this, file);
      };
    }
  };

  // ---------------------------------------------------------------------------
  // 启动
  // ---------------------------------------------------------------------------
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }

})();
