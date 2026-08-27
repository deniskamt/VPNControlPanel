// Минимум клиентского кода: панель работает и с выключенным JS,
// здесь только удобства — живое обновление статусов, модалки, копирование.

(function () {
  "use strict";

  // Блок с data-refresh="/url" сам перезапрашивает свой HTML.
  document.querySelectorAll("[data-refresh]").forEach(function (node) {
    var url = node.getAttribute("data-refresh");
    var every = parseInt(node.getAttribute("data-refresh-every") || "15", 10) * 1000;

    setInterval(function () {
      if (document.hidden) return;
      fetch(url, { headers: { "X-Requested-With": "fetch" } })
        .then(function (response) {
          return response.ok ? response.text() : null;
        })
        .then(function (html) {
          if (html !== null) node.innerHTML = html;
        })
        .catch(function () {
          /* сеть моргнула — просто ждём следующего тика */
        });
    }, every);
  });

  // Раскрывающиеся формы: <button data-toggle="#id">
  document.addEventListener("click", function (event) {
    var trigger = event.target.closest("[data-toggle]");
    if (!trigger) return;
    var target = document.querySelector(trigger.getAttribute("data-toggle"));
    if (!target) return;
    event.preventDefault();
    target.hidden = !target.hidden;
    if (!target.hidden) {
      var field = target.querySelector("input, select, textarea");
      if (field) field.focus();
    }
  });

  // Подтверждение перед опасными действиями.
  document.addEventListener("submit", function (event) {
    var form = event.target;
    var question = form.getAttribute("data-confirm");
    if (question && !window.confirm(question)) event.preventDefault();
  });

  // Кнопки отправляют обычные формы, и после каждой страница
  // перезагружается с самого верха. Запоминаем место и возвращаемся туда же.
  var SCROLL_KEY = "scroll:" + location.pathname;

  document.addEventListener("submit", function () {
    try {
      sessionStorage.setItem(SCROLL_KEY, String(window.scrollY));
    } catch (error) {
      /* приватный режим — просто не запомним */
    }
  });

  window.addEventListener("pageshow", function () {
    var saved = null;
    try {
      saved = sessionStorage.getItem(SCROLL_KEY);
      sessionStorage.removeItem(SCROLL_KEY);
    } catch (error) {
      return;
    }
    if (saved !== null) window.scrollTo(0, parseInt(saved, 10) || 0);
  });

  // Копирование ссылок подписки.
  document.addEventListener("click", function (event) {
    var button = event.target.closest("[data-copy]");
    if (!button) return;
    event.preventDefault();

    var value = button.getAttribute("data-copy");
    var source = document.querySelector(value);
    var text = source ? source.value || source.textContent : value;

    var done = function () {
      var original = button.textContent;
      button.textContent = "Скопировано";
      setTimeout(function () {
        button.textContent = original;
      }, 1500);
    };

    if (navigator.clipboard) {
      navigator.clipboard.writeText(text).then(done, done);
    } else if (source && source.select) {
      source.select();
      document.execCommand("copy");
      done();
    }
  });
})();
