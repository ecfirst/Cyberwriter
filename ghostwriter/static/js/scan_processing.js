/* Scan Processing page: uploads, removes, clear, and refresh.
 *
 * Every card is server-rendered; after any state change the page reloads the
 * contents of #scan-processing-root from the same URL (the project page does the
 * same for its tabs). Handlers are delegated on `document` so they survive that
 * replacement. The Nexpose upload is processed in the background: the page learns
 * it finished through the `ghostwriter:notification` event that base_generic.html
 * dispatches for every WebSocket message, with a 30 s polling fallback.
 */
(function () {
  'use strict';

  const root = document.getElementById('scan-processing-root');
  if (!root) {
    return;
  }

  const pageUrl = root.dataset.pageUrl || window.location.pathname;
  const uploadUrl = root.dataset.uploadUrl;
  const stateUrl = root.dataset.stateUrl;
  const clearUrl = root.dataset.clearUrl;
  const token = root.dataset.token || '';
  const NEXPOSE_FIELD = 'nexpose_xml';

  let pollTimer = null;
  let refreshing = false;

  const getCsrfToken = function () {
    const cookieString = document.cookie || '';
    const cookies = cookieString.split(';');
    for (let i = 0; i < cookies.length; i += 1) {
      const cookie = cookies[i].trim();
      if (cookie.startsWith('csrftoken=')) {
        return decodeURIComponent(cookie.substring('csrftoken='.length));
      }
    }
    return root.dataset.csrfToken || null;
  };

  const toast = function (type, message, title) {
    if (typeof displayToastTop === 'function') {
      displayToastTop({type: type, string: message, title: title || 'Scan Processing'});
    } else {
      console.log(type + ': ' + message);
    }
  };

  const setButtonLoading = function (button, text) {
    if (!button) {
      return;
    }
    const defaultText = button.getAttribute('data-default-text') || button.textContent.trim();
    button.setAttribute('data-default-text', defaultText);
    button.innerHTML = '<span class="spinner-border spinner-border-sm mr-2" role="status" aria-hidden="true"></span>' + text;
    button.disabled = true;
  };

  const clearButtonLoading = function (button) {
    if (!button || !button.isConnected) {
      return;
    }
    const defaultText = button.getAttribute('data-default-text');
    if (defaultText) {
      button.innerHTML = defaultText;
    }
    button.disabled = false;
  };

  const parseJsonResponse = function (response, fallbackMessage) {
    return response.text().then(function (text) {
      let data = null;
      if (text) {
        try {
          data = JSON.parse(text);
        } catch (parseError) {
          data = null;
        }
      }
      if (!response.ok || data === null) {
        let message = (data && data.error) ? data.error : fallbackMessage;
        if (!response.ok && (!data || !data.error)) {
          if (response.status === 413) {
            message = 'That file is too large to upload.';
          } else if (response.status === 504 || response.status === 502 || response.status === 503) {
            message = 'The server took too long to process that file. It may be too large.';
          } else if (response.status === 403) {
            message = 'Your session has expired. Reload the page and try again.';
          } else {
            message = fallbackMessage + ' (server returned status ' + response.status + ').';
          }
        } else if (response.ok && data === null) {
          message = 'The server returned an unexpected response.';
        }
        throw new Error(message);
      }
      data.__status = response.status;
      return data;
    });
  };

  const isProcessing = function () {
    return root.dataset.processing === '1';
  };

  const syncProcessingFlagFromDom = function () {
    const notice = root.querySelector('[data-scan-processing]');
    root.dataset.processing = (notice && !notice.hidden) ? '1' : '0';
  };

  const showColumnError = function (column, message) {
    const box = document.getElementById('scan-' + column + '-error');
    if (box) {
      box.textContent = message;
      box.hidden = false;
    }
  };

  const setProcessing = function (active) {
    root.dataset.processing = active ? '1' : '0';
    const notice = root.querySelector('[data-scan-processing]');
    if (notice) {
      notice.hidden = !active;
    }
    document.querySelectorAll('[data-scan-disable-while-processing]').forEach(function (button) {
      button.disabled = active;
    });
    const column = document.getElementById('scan-nexpose-column');
    if (column) {
      if (active) {
        column.setAttribute('aria-busy', 'true');
      } else {
        column.removeAttribute('aria-busy');
      }
    }
  };

  let refreshQueued = false;
  const refreshRoot = function (done) {
    if (refreshing) {
      // A completion notice can land while the post-upload refresh is still in
      // flight; run one more refresh afterwards instead of dropping it.
      refreshQueued = true;
      return;
    }
    refreshing = true;
    $(root).load(pageUrl + ' #scan-processing-root > *', function (responseText, status) {
      refreshing = false;
      if (status === 'error' || !root.children.length) {
        window.location.reload();
        return;
      }
      syncProcessingFlagFromDom();
      scheduleStatePoll();
      if (typeof done === 'function') {
        done();
      }
      if (refreshQueued) {
        refreshQueued = false;
        refreshRoot();
      }
    });
  };

  const scheduleStatePoll = function () {
    if (pollTimer !== null || !isProcessing() || !stateUrl) {
      return;
    }
    pollTimer = window.setTimeout(pollState, 30000);
  };

  const pollState = function () {
    pollTimer = null;
    if (!isProcessing()) {
      return;
    }
    fetch(stateUrl, {method: 'GET', headers: {'Accept': 'application/json'}, credentials: 'same-origin'})
      .then(function (response) {
        return parseJsonResponse(response, 'Unable to refresh scan processing state');
      })
      .then(function (data) {
        const artifacts = (data && data.data_artifacts) || {};
        const stillProcessing = artifacts.processing_uploads || {};
        if (stillProcessing[NEXPOSE_FIELD]) {
          scheduleStatePoll();
          return;
        }
        setProcessing(false);
        refreshRoot();
      })
      .catch(function (error) {
        console.error(error);
        scheduleStatePoll();
      });
  };

  const uploadScanFile = function (uploadField, column, file, button) {
    if (!file) {
      return;
    }
    if (!file.name || !file.name.toLowerCase().endsWith('.xml')) {
      toast('error', 'Select an XML export (.xml) to upload.');
      return;
    }
    if (!uploadUrl) {
      toast('error', 'Upload endpoint is not configured.');
      return;
    }

    const formData = new FormData();
    formData.append('file', file);
    formData.append('upload_field', uploadField);
    formData.append('token', token);

    setButtonLoading(button, 'Uploading...');
    fetch(uploadUrl, {
      method: 'POST',
      headers: {'X-CSRFToken': getCsrfToken() || '', 'Accept': 'application/json'},
      body: formData,
      credentials: 'same-origin',
    })
      .then(function (response) {
        return parseJsonResponse(response, 'Unable to upload ' + file.name);
      })
      .then(function (data) {
        if (data.__status === 202 && data.queued) {
          setProcessing(true);
          toast('info', data.message || 'Upload received. Processing in the background…');
          refreshRoot();
          return;
        }
        if (data.warning) {
          toast('warning', data.warning);
        } else {
          toast('success', data.message || (file.name + ' processed.'));
        }
        refreshRoot();
      })
      .catch(function (error) {
        clearButtonLoading(button);
        toast('error', error.message || ('Unable to upload ' + file.name));
        showColumnError(column, error.message || ('Unable to upload ' + file.name));
      });
  };

  const postJson = function (url, button, loadingText, fallbackMessage) {
    setButtonLoading(button, loadingText);
    return fetch(url, {
      method: 'POST',
      headers: {
        'X-CSRFToken': getCsrfToken() || '',
        'Accept': 'application/json',
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({token: token}),
      credentials: 'same-origin',
    })
      .then(function (response) {
        return parseJsonResponse(response, fallbackMessage);
      })
      .catch(function (error) {
        clearButtonLoading(button);
        throw error;
      });
  };

  // -- Delegated handlers ---------------------------------------------------

  document.addEventListener('click', function (event) {
    const pick = event.target.closest('.js-scan-pick');
    if (pick && root.contains(pick)) {
      event.preventDefault();
      const input = document.querySelector(pick.getAttribute('data-target'));
      if (input) {
        input.click();
      }
      return;
    }

    const remove = event.target.closest('.js-scan-remove');
    if (remove && root.contains(remove)) {
      event.preventDefault();
      const column = remove.getAttribute('data-scan-column') || 'nexpose';
      postJson(remove.getAttribute('data-remove-url'), remove, 'Removing...', 'Unable to remove that data')
        .then(function () {
          toast('success', 'Data removed.');
          refreshRoot();
        })
        .catch(function (error) {
          toast('error', error.message);
          showColumnError(column, error.message);
        });
      return;
    }

    const clear = event.target.closest('.js-scan-clear');
    if (clear) {
      event.preventDefault();
      if (!window.confirm('Clear all scan processing data? This cannot be undone.')) {
        return;
      }
      postJson(clearUrl, clear, 'Clearing...', 'Unable to clear the session')
        .then(function () {
          toast('success', 'Scan processing data cleared.');
          window.location.reload();
        })
        .catch(function (error) {
          toast('error', error.message);
        });
    }
  });

  document.addEventListener('change', function (event) {
    const input = event.target;
    if (!(input instanceof HTMLInputElement) || input.type !== 'file' || !root.contains(input)) {
      return;
    }
    if (!input.hasAttribute('data-upload-field')) {
      return; // the Additional Data form submits explicitly
    }
    const file = input.files && input.files[0];
    const button = root.querySelector('.js-scan-pick[data-target="#' + input.id + '"]');
    const uploadField = input.getAttribute('data-upload-field');
    const column = input.getAttribute('data-scan-column') || 'nexpose';
    input.value = '';
    uploadScanFile(uploadField, column, file, button);
  });

  document.addEventListener('submit', function (event) {
    const form = event.target.closest('.js-scan-upload-form');
    if (!form || !root.contains(form)) {
      return;
    }
    event.preventDefault();
    const input = form.querySelector('input[type="file"]');
    const file = input && input.files && input.files[0];
    if (!file) {
      toast('error', 'Select a file to upload.');
      return;
    }
    const button = form.querySelector('button[type="submit"]');
    uploadScanFile(form.getAttribute('data-upload-field'), form.getAttribute('data-scan-column') || 'nexpose', file, button);
  });

  document.addEventListener('ghostwriter:notification', function (event) {
    const detail = event && event.detail;
    if (!detail || detail.event !== 'scan_processing_complete') {
      return;
    }
    if (detail.token && token && String(detail.token) !== token) {
      return;
    }
    if (pollTimer !== null) {
      window.clearTimeout(pollTimer);
      pollTimer = null;
    }
    setProcessing(false);
    refreshRoot();
  });

  // Resume polling if the page was loaded while an upload is processing.
  scheduleStatePoll();
})();
