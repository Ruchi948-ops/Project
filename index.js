function searchPatches() {
    let query = document.getElementById("searchInput").value;
    fetch(`/search?query=${query}`)
        .then(response => response.json())
        .then(data => {
            let list = document.getElementById("patchList");
            list.innerHTML = "";
            data.forEach(patch => {
                let listItem = document.createElement("li");
                listItem.innerHTML = `${patch} - <a href="/download/${patch}">Download</a>`;
                list.appendChild(listItem);
            });
        });
}
