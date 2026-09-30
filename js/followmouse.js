var hoverImage = document.getElementById("hoverImage");
var hoverWrap = document.getElementById("hoverWrap");

document.addEventListener("mousemove", getMouse);
// The image flips to stay inside the window, so it is placed again whenever
// its size or the window's edges change under a still pointer.
hoverImage.addEventListener("load", followMouse);
window.addEventListener("scroll", followMouse);
window.addEventListener("resize", followMouse);

var mouseLoc = {x: 0, y: 0};

function getMouse(e){
    mouseLoc.x = e.pageX + 10;
    mouseLoc.y = e.pageY + 10;
    followMouse();
}

function followMouse(){
    var el = hoverWrap || hoverImage;
    var w = hoverImage.width;
    var h = hoverImage.height;
    if (mouseLoc.x + w > window.innerWidth + window.pageXOffset) {
        el.style.left = (mouseLoc.x - w - 20) + "px";
    } else {
        el.style.left = mouseLoc.x + "px";
    }
    if (mouseLoc.y + h > window.innerHeight + window.pageYOffset) {
        el.style.top = (mouseLoc.y - h - 20) + "px";
    } else {
        el.style.top = mouseLoc.y + "px";
    }
}
