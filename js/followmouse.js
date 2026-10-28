var hoverImage = document.getElementById("hoverImage");
var hoverWrap = document.getElementById("hoverWrap");

document.addEventListener("mousemove", getMouse);
// The image flips to stay inside the window, so it is placed again whenever
// its size or the window's edges change under a still pointer.
hoverImage.addEventListener("load", followMouse);
window.addEventListener("scroll", followMouse);
window.addEventListener("resize", followMouse);

// Kept in window coordinates: a scroll moves the page under a still
// pointer, so its page position is only known when the image is placed.
var mouseLoc = {x: 0, y: 0};

function getMouse(e){
    mouseLoc.x = e.clientX;
    mouseLoc.y = e.clientY;
    followMouse();
}

function followMouse(){
    var el = hoverWrap || hoverImage;
    var w = hoverImage.width;
    var h = hoverImage.height;
    var x = mouseLoc.x + window.pageXOffset + 10;
    var y = mouseLoc.y + window.pageYOffset + 10;
    if (x + w > window.innerWidth + window.pageXOffset) {
        el.style.left = (x - w - 20) + "px";
    } else {
        el.style.left = x + "px";
    }
    if (y + h > window.innerHeight + window.pageYOffset) {
        el.style.top = (y - h - 20) + "px";
    } else {
        el.style.top = y + "px";
    }
}
