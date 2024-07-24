const url = "/api/suggest?all=true";

/*
 * Query Scryfall to retrieve the list of card names.
 */
async function fetchNames(sealed) {
    let cardNames = await fetch(url + "&sealed=" + sealed)
        // Transform the data into json
        .then(response => response.json())
    return cardNames;
}
