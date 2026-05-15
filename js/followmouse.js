var hoverImage = document.getElementById("hoverImage");
var hoverWrap = document.getElementById("hoverWrap");

document.addEventListener("mousemove", getMouse);

setInterval(followMouse, 10);

var mouseLoc = {x: 0, y: 0};

function getMouse(e){
    mouseLoc.x = e.pageX + 10;
    mouseLoc.y = e.pageY + 10;
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
