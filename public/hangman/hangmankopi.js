let feil = 0;
let riktig = "";
let lengde = 0;
let posisjon = [];
let feilliste = [];
const ord = ["tilfeldig", "neshorn", "regnbyger", "tåkedotter", "ørnerede", "dagligvarer", "skogbruk", "skolegang"];

function gjett() {
    let vant = true;
    let funnet = false;
    let bokstav = document.getElementById("gjettInput").value.trim().toLowerCase();
    document.getElementById("gjettInput").value="";
    if (bokstav === "" || feilliste.includes(bokstav)) {
        console.log("Skriv inn en bokstav")
        return;
    }
    for (let i = 0; i < lengde; i++) {
        if (bokstav === riktig.charAt(i)) {
            posisjon.push(i)
            funnet = true;
        }
    }
    if (funnet === false) {
        feil++;
        feilliste.push(bokstav);
    }

    for (i = 1; i <= feil; i++) {
        let lagindex = i + 1;
        document.getElementById("lag" + lagindex).style.display="block";
    }
    let gjetteplass = "";
    for (let i = 0; i < lengde; i++) {
        if (posisjon.includes(i)) {
            gjetteplass += riktig.charAt(i) + " ";
        }
        else {
            gjetteplass += "_ ";
            vant = false;
        } 
    }
    let feilbokstaver = "Feil: "
    for (let i = 0; i < feilliste.length; i++) {
        feilbokstaver += feilliste[i] + " ";
    }
    if (vant === true) {
        document.getElementById("ferdigknap").style.display="inline";
        document.getElementById("resultat").innerText="Gratulerer, du vant! :)";
        document.getElementById("gjettKnapp").style.display="none"
    }
    else if (feil === 6) {
        document.getElementById("ferdigknap").style.display="inline";
        document.getElementById("resultat").innerText="Å nei! Du tapte! :(";
        document.getElementById("gjettKnapp").style.display="none"
    }
    //Noe som fikser den "Du vant/tapte" tingen jeg snakket om i html dellen//
    //No som gjør at man kan tape f.eks feil blir større en et førbestemt tall//
    document.getElementById("feilplass").innerText=feilbokstaver;
    document.getElementById("gjetteplass").innerText=gjetteplass;
}

function HM() {
    document.getElementById("gjettKnapp").addEventListener("click",gjett);
    document.getElementById("lag1").style.display="block";
    riktig = ord[Math.floor(Math.random() * 8)];
    lengde = riktig.length;
    posisjon =[];
    let gjetteplass = "";
    for (let i = 0; i < lengde; i++) {
        gjetteplass += "_ ";
    }
    document.getElementById("gjetteplass").innerText=gjetteplass;
}
