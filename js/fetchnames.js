async function fetchNames(sealed) {
    let cardNames = await fetch("/api/suggest?all=true&sealed=" + sealed)
        // Transform the data into json
        .then(response => response.json())
    return cardNames;
}
