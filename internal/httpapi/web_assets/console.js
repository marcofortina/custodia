// Copyright (c) 2026 Marco Fortina
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Custodia.
// Custodia is distributed under the GNU Affero General Public License v3.0.
// See the accompanying LICENSE file for details.

(() => {
  const refreshStorageKey = 'custodia.console.refreshSeconds';
  const paginationStoragePrefix = 'custodia.console.paginationPage.';
  const allowedRefreshIntervals = new Set(['5', '10', '15', '30']);
  let refreshTimeout = null;
  let refreshCountdown = null;
  let refreshInFlight = false;

  const selectMain = (doc) => doc.querySelector('#console-main');

  const clearRefreshTimers = () => {
    if (refreshTimeout) {
      window.clearTimeout(refreshTimeout);
      refreshTimeout = null;
    }
    if (refreshCountdown) {
      window.clearInterval(refreshCountdown);
      refreshCountdown = null;
    }
  };

  const selectedRefreshSeconds = () => {
    const stored = window.localStorage.getItem(refreshStorageKey);
    return allowedRefreshIntervals.has(stored) ? stored : '10';
  };

  const setRefreshStatus = (control, text) => {
    const status = control.querySelector('[data-refresh-status]');
    if (status) status.textContent = text;
  };

  const setLastUpdated = (root = document) => {
    const stamp = root.querySelector('[data-refresh-updated]') || document.querySelector('[data-refresh-updated]');
    if (!stamp) return;
    stamp.textContent = `Last updated ${new Date().toLocaleTimeString()}`;
  };

  const isConsoleFormFieldFocused = () => {
    const active = document.activeElement;
    return Boolean(active && active.closest('#console-main') && active.matches('input, select, textarea'));
  };

  const scheduleRefresh = (control) => {
    clearRefreshTimers();
    if (!control || refreshInFlight) return;
    if (document.visibilityState === 'hidden') {
      setRefreshStatus(control, 'Refresh paused');
      return;
    }

    const select = control.querySelector('[data-refresh-interval]');
    const seconds = Number.parseInt((select && select.value) || selectedRefreshSeconds(), 10);
    if (!Number.isFinite(seconds) || seconds <= 0) return;

    let remaining = seconds;
    setRefreshStatus(control, `Refresh in ${remaining}s`);
    refreshCountdown = window.setInterval(() => {
      remaining -= 1;
      if (remaining > 0) setRefreshStatus(control, `Refresh in ${remaining}s`);
    }, 1000);
    refreshTimeout = window.setTimeout(() => {
      if (document.visibilityState === 'hidden') {
        setRefreshStatus(control, 'Refresh paused');
        return;
      }
      if (isConsoleFormFieldFocused()) {
        setRefreshStatus(control, 'Refresh paused while editing');
        scheduleRefresh(control);
        return;
      }
      refreshCurrentView(control).catch(() => {
        window.location.reload();
      });
    }, seconds * 1000);
  };

  const paginationStorageKey = (container) => `${paginationStoragePrefix}${window.location.pathname}${window.location.search}:${container.dataset.paginationLabel || 'table'}`;

  const initPaginatedTables = (root = document) => {
    root.querySelectorAll('[data-console-pagination="true"]').forEach((container) => {
      if (container.dataset.paginationReady === 'true') return;
      const pageSize = Number.parseInt(container.dataset.pageSize || '10', 10);
      const tbody = container.querySelector('tbody');
      if (!tbody || !Number.isFinite(pageSize) || pageSize <= 0) return;

      const rows = Array.from(tbody.querySelectorAll('tr'));
      if (rows.length <= pageSize) return;

      container.dataset.paginationReady = 'true';
      const key = paginationStorageKey(container);
      const storedPage = Number.parseInt(window.sessionStorage.getItem(key) || '0', 10);
      const pageCount = Math.ceil(rows.length / pageSize);
      let currentPage = Number.isFinite(storedPage) ? Math.min(Math.max(storedPage, 0), pageCount - 1) : 0;
      const nav = document.createElement('nav');
      nav.className = 'console-pagination';
      nav.setAttribute('aria-label', container.dataset.paginationLabel || 'Table pagination');
      nav.innerHTML = '<button type="button" data-pagination-first>First</button><button type="button" data-pagination-prev>Previous</button><span class="console-pagination__status" aria-live="polite"></span><button type="button" data-pagination-next>Next</button><button type="button" data-pagination-last>Last</button>';
      container.insertAdjacentElement('afterend', nav);

      const firstButton = nav.querySelector('[data-pagination-first]');
      const previousButton = nav.querySelector('[data-pagination-prev]');
      const nextButton = nav.querySelector('[data-pagination-next]');
      const lastButton = nav.querySelector('[data-pagination-last]');
      const status = nav.querySelector('.console-pagination__status');
      const update = () => {
        const start = currentPage * pageSize;
        const end = start + pageSize;
        rows.forEach((row, index) => {
          row.hidden = index < start || index >= end;
        });
        status.textContent = `Showing ${start + 1}–${Math.min(end, rows.length)} of ${rows.length} · Page ${currentPage + 1} of ${pageCount}`;
        window.sessionStorage.setItem(key, String(currentPage));
        firstButton.disabled = currentPage === 0;
        previousButton.disabled = currentPage === 0;
        nextButton.disabled = currentPage === pageCount - 1;
        lastButton.disabled = currentPage === pageCount - 1;
      };
      const goToPage = (page) => {
        currentPage = Math.min(Math.max(page, 0), pageCount - 1);
        update();
      };

      firstButton.addEventListener('click', () => goToPage(0));
      previousButton.addEventListener('click', () => goToPage(currentPage - 1));
      nextButton.addEventListener('click', () => goToPage(currentPage + 1));
      lastButton.addEventListener('click', () => goToPage(pageCount - 1));
      update();
    });
  };

  const initRefreshControls = (root = document) => {
    const control = root.querySelector('[data-console-refresh-control]') || document.querySelector('[data-console-refresh-control]');
    clearRefreshTimers();
    if (!control || control.closest('.console-auth-shell') || control.closest('.console-error-shell')) return;

    const select = control.querySelector('[data-refresh-interval]');
    if (select) {
      const seconds = selectedRefreshSeconds();
      select.value = seconds;
      if (control.dataset.refreshReady !== 'true') {
        select.addEventListener('change', () => {
          const value = allowedRefreshIntervals.has(select.value) ? select.value : '10';
          window.localStorage.setItem(refreshStorageKey, value);
          select.value = value;
          scheduleRefresh(control);
        });
      }
    }

    const refreshButton = control.querySelector('[data-refresh-now]');
    if (refreshButton && control.dataset.refreshReady !== 'true') {
      refreshButton.addEventListener('click', () => {
        refreshCurrentView(control).catch(() => {
          window.location.reload();
        });
      });
    }

    control.dataset.refreshReady = 'true';
    scheduleRefresh(control);
  };

  const swapMain = async (url, options = {}) => {
    const { focus = true, scroll = true } = options;
    clearRefreshTimers();
    const response = await fetch(url, { headers: { 'HX-Request': 'true' }, credentials: 'same-origin' });
    if (!response.ok) {
      window.location.href = url;
      return;
    }
    const text = await response.text();
    const parsed = new DOMParser().parseFromString(text, 'text/html');
    const nextMain = selectMain(parsed);
    const currentMain = document.querySelector('#console-main');
    if (!nextMain || !currentMain) {
      window.location.href = url;
      return;
    }
    const responseURL = new URL(response.url, window.location.href);
    if (responseURL.pathname === '/web/login' || nextMain.classList.contains('console-auth-shell')) {
      window.location.href = responseURL.href;
      return;
    }
    document.title = parsed.title || document.title;
    currentMain.replaceWith(nextMain);
    initPaginatedTables(nextMain);
    initRefreshControls(nextMain);
    if (focus) nextMain.focus({ preventScroll: true });
    if (scroll) window.scrollTo({ top: 0, behavior: 'smooth' });
  };

  const refreshCurrentView = async (control) => {
    if (refreshInFlight) return;
    refreshInFlight = true;
    clearRefreshTimers();
    setRefreshStatus(control, 'Refreshing…');
    try {
      await swapMain(window.location.href, { focus: false, scroll: false });
      setLastUpdated();
    } finally {
      refreshInFlight = false;
      initRefreshControls();
    }
  };

  document.addEventListener('click', (event) => {
    const link = event.target.closest('a[href]');
    if (!link || !link.closest('[hx-boost="true"]')) return;
    const url = new URL(link.href, window.location.href);
    if (url.origin !== window.location.origin || !url.pathname.startsWith('/web/')) return;
    event.preventDefault();
    history.pushState(null, '', url);
    swapMain(url).catch(() => { window.location.href = url; });
  });

  document.addEventListener('submit', (event) => {
    const form = event.target.closest('form[hx-get]');
    if (!form) return;
    event.preventDefault();
    const url = new URL(form.getAttribute('hx-get'), window.location.href);
    new FormData(form).forEach((value, key) => {
      const text = String(value).trim();
      if (text !== '') url.searchParams.set(key, text);
    });
    history.pushState(null, '', url);
    swapMain(url).catch(() => { window.location.href = url; });
  });

  window.addEventListener('popstate', () => {
    swapMain(window.location.href).catch(() => { window.location.reload(); });
  });

  document.addEventListener('visibilitychange', () => {
    if (document.visibilityState === 'visible') initRefreshControls();
    else clearRefreshTimers();
  });

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => {
      initPaginatedTables();
      setLastUpdated();
      initRefreshControls();
    });
  } else {
    initPaginatedTables();
    setLastUpdated();
    initRefreshControls();
  }
})();
