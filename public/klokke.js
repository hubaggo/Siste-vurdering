setInterval(klokke, 1000)

function klokke() {
    let date = new Date();
    let t = date.getHours();
    let m = date.getMinutes();
    let s = date.getSeconds();

    if (s < 10) {
        s = "0" + s;
    }
    if (t < 10) {
        t = "0" + t;
    }

    if (m < 10) {
        m = "0" + m;
    }

    let tid = "Klokken er ganske nøyaktig " + t + ":" + m +":" + s;

    console.log(tid)

    document.getElementById("klokke").innerText = tid
}

klokke();