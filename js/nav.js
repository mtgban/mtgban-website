(function () {
  "use strict";

  document.addEventListener("DOMContentLoaded", function () {
    const toggle = document.querySelector(".nav-toggle");
    const menu = document.querySelector(".nav-menu");

    if (toggle && menu) {
      toggle.addEventListener("click", function (e) {
        e.preventDefault();

        if (menu.classList.contains("active")) {
          menu.style.opacity = "0";
          menu.style.transform = "translateY(-10px)";
          setTimeout(() => {
            menu.classList.remove("active");
            menu.style.opacity = "none";
          }, 300);
          this.classList.remove("active");
        } else {
          menu.style.display = "block";
          menu.offsetHeight;
          menu.classList.add("active");
          menu.style.opacity = "1";
          menu.style.transform = "translateY(0)";
          this.classList.add("active");
        }
      });

      menu.querySelectorAll("a").forEach(function (link) {
        link.addEventListener("click", function () {
          menu.style.opacity = "0";
          setTimeout(function () {
            menu.classList.remove("active");
            menu.style.display = "none";
            toggle.classList.remove("active");
          }, 300);
        });
      });

      document.addEventListener("click", function (evt) {
        if (
          menu.classList.contains("active") &&
          !toggle.contains(evt.target) &&
          !menu.contains(evt.target)
        ) {
          menu.style.opacity = "0";
          setTimeout(() => {
            menu.classList.remove("active");
            menu.style.display = "none";
            toggle.classList.remove("active");
          }, 300);
        }
      });
    }
  });
})();
