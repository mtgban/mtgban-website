const isBrowser = typeof window !== 'undefined'

// Inject base CSS for view transitions
const injectBaseStyles = () => {
  if (isBrowser) {
    const styleId = 'theme-switch-base-style'
    if (!document.getElementById(styleId)) {
      const style = document.createElement('style')
      style.id = styleId
      const isHighResolution = window.innerWidth >= 3000 || window.innerHeight >= 2000

      style.textContent = `
        ::view-transition-old(root),
        ::view-transition-new(root) {
          mix-blend-mode: normal;
          ${isHighResolution ? 'transform: translateZ(0);' : ''}
        }
        
        ${isHighResolution ? `
        ::view-transition-group(root),
        ::view-transition-image-pair(root),
        ::view-transition-old(root),
        ::view-transition-new(root) {
          backface-visibility: hidden;
          perspective: 1000px;
          transform: translate3d(0, 0, 0);
        }
        ` : ''}
      `
      document.head.appendChild(style)
    }
  }
}

const mtgbanMask = (blur = 0) => {
  const viewBox = '0 0 24 24'
  const blurFilter = blur > 0 ? `<filter id="blur"><feGaussianBlur stdDeviation="${blur}" /></filter>` : ''
  const filterAttr = blur > 0 ? 'filter="url(%23blur)"' : ''
  const BANPATH = "M112 24.42c11.27-1.37 26.2.48 37 3.92 17.1 5.46 31.73 14.22 43.83 27.66 33.86 37.61 32.15 96.8-2.87 133-7.89 8.15-18.57 15.55-28.96 20.14-13.11 5.79-27.64 9.02-42 8.86-10.13-.12-24.54-3.15-34-6.81-12.23-4.74-23.56-12.12-32.96-21.28-37.88-36.9-36.85-99.28-.95-136.9C68.12 35.17 88.3 27.86 112 24.42Zm-2 6.87C79.4 35.96 52.92 52.3 39.32 81 16.43 129.29 39.08 189.22 91 206.33c7.34 2.42 16.27 4.58 24 4.67 16.46.19 28.84-.93 44-8.26 11.5-5.55 22.02-12.89 30.25-22.74 30.23-36.23 28.97-90.6-5.29-123.91-8.74-8.5-20.54-15.6-31.96-19.86-13.13-4.91-28.1-6.24-42-4.94ZM185 78c2.65 4.55 2.69 16.33 3.09 22l2.74 28 2.17 22-16.5.89-4.3-7.89-8.2-20 3 29c-2.58.73-13.42 2.46-15.4.96-1.72-1.29-1.53-4.05-1.61-5.96l-1.08-13-1.74-17L144 82l17-1 12 29-3-30 15-2Zm-84 80 2-62 1.9-9.26 8.1-1.83L131 83l8.88 37 8.12 34c-3.03.54-16.36 2.46-18.42.96-3.34-2.42-.91-9.62-5.73-10.95-1.11-.29-2.71-.07-3.85 0V157l-19 1Zm20-50h-2v23l6-1-4-22ZM49 90l26-1c3.04.02 6.19-.07 9 1.31 7.28 3.6 11.66 18.32 7.69 25.51-1.31 2.36-3.55 3.69-5.69 5.18 12 3.13 11.13 14.85 11 25-.06 3.91-.25 7.53-3.39 10.35-3.63 3.26-9.05 3.33-13.61 3.81L55 162l-6-72Zm25 12h-5l1 15c7.47-1.72 5.07-9.04 4-15Zm-1 46c1.67-.62 2.88-.79 3.98-2.42 1.72-2.55.78-13.71-1.58-15.56-1.24-.97-2.92-.9-4.4-1.02l2 19Z"

  return `url('data:image/svg+xml,<svg xmlns="http://www.w3.org/2000/svg" viewBox="${viewBox}"><defs>${blurFilter}</defs><path fill="white" d="${BANPATH}" ${filterAttr}/></svg>')`
}

async function toggleThemeWithTransition() {
  const styleId = 'theme-switch-style'
  const duration = 750
  const blurAmount = 0
  const easing = 'ease-in-out'

  if (!document.startViewTransition || window.matchMedia('(prefers-reduced-motion: reduce)').matches) {
    document.body.classList.toggle('dark-theme')
    return
  }

  const existingStyle = document.getElementById(styleId)
  if (existingStyle) {
    existingStyle.remove()
  }

  const x = window.innerWidth / 2
  const y = window.innerHeight / 2

  const topLeft = Math.hypot(x, y)
  const topRight = Math.hypot(window.innerWidth - x, y)
  const bottomLeft = Math.hypot(x, window.innerHeight - y)
  const bottomRight = Math.hypot(window.innerWidth - x, window.innerHeight - y)
  const maxRadius = Math.max(topLeft, topRight, bottomLeft, bottomRight)

  const viewportSize = Math.max(window.innerWidth, window.innerHeight) + 200
  const isHighResolution = window.innerWidth >= 3000 || window.innerHeight >= 2000
  const scaleFactor = isHighResolution ? 2.5 : 5
  const optimalMaskSize = isHighResolution
    ? Math.min(viewportSize * scaleFactor, 5000)
    : viewportSize * scaleFactor

  const styleElement = document.createElement('style')
  styleElement.id = styleId

  const blurFactor = isHighResolution ? 1.5 : 1.2
  const finalMaskSize = Math.max(optimalMaskSize, maxRadius * 2.5)
  const maskFunction = mtgbanMask(blurAmount * blurFactor)

  styleElement.textContent = `
    ::view-transition-group(root) {
      animation-duration: ${duration}ms;
      animation-timing-function: ${
        isHighResolution
          ? 'cubic-bezier(0.2, 0, 0.2, 1)'
          : 'linear(0 0%, 0.2342 12.49%, 0.4374 24.99%, 0.6093 37.49%, 0.6835 43.74%, 0.7499 49.99%, 0.8086 56.25%, 0.8593 62.5%, 0.9023 68.75%, 0.9375 75%, 0.9648 81.25%, 0.9844 87.5%, 0.9961 93.75%, 1 100%)'
      };
      will-change: transform;
    }

    ::view-transition-new(root) {
      mask-image: ${maskFunction};
      mask-repeat: no-repeat;
      mask-size: 0px;
      mask-position: ${x}px ${y}px;
      animation: maskScale ${duration * 1.5}ms ${easing};
      transform-origin: ${x}px ${y}px;
      will-change: mask-size, mask-position;
    }

    ::view-transition-old(root),
    .dark-theme::view-transition-old(root) {
      animation: maskScale ${duration}ms ${easing};
      transform-origin: ${x}px ${y}px;
      z-index: -1;
      will-change: mask-size, mask-position;
    }

    @keyframes maskScale {
      0% {
        mask-size: 0px;
        mask-position: ${x}px ${y}px;
      }
      100% {
        mask-size: ${finalMaskSize}px;
        mask-position: ${x - finalMaskSize / 2}px ${y - finalMaskSize / 2}px;
      }
    }
  `
  document.head.appendChild(styleElement)

  const transition = document.startViewTransition(() => {
    document.body.classList.toggle('dark-theme')
  })

  transition.finished
    .then(() => {
      setTimeout(() => {
        const styleElement = document.getElementById(styleId)
        if (styleElement) {
          styleElement.remove()
        }
      }, 50)
    })
    .catch(() => {
      setTimeout(() => {
        const styleElement = document.getElementById(styleId)
        if (styleElement) {
          styleElement.remove()
        }
      }, duration)
    })
}

// Initialize
injectBaseStyles()

// Get elements - they're already in the DOM since script is at the bottom of the label
const themeSwitch = document.querySelector('.switch input[type="checkbox"]')
const themeTitle = document.querySelector('.switch .slider')

if (themeSwitch && themeTitle) {
  // Set initial state based on localStorage
  if (localStorage.getItem("theme") === "dark") {
    themeSwitch.checked = true
    themeTitle.title = "Nightbound"
  } else {
    themeTitle.title = "Daybound"
  }

  // Add event listener with transition
  themeSwitch.addEventListener('change', async () => {
    await toggleThemeWithTransition()

    let theme = "light"

    if (document.body.classList.contains("dark-theme")) {
      theme = "dark"
      themeTitle.title = "Nightbound"
    } else {
      themeTitle.title = "Daybound"
    }

    localStorage.setItem("theme", theme)
  })
}

