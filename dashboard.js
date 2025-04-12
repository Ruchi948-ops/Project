let patches = [];

function uploadPatch() {
    const form = document.getElementById("uploadForm");
    form.submit();
}

function downloadPatch(index) {
    alert(`Downloading: ${patches[index].name}`);
    patches[index].status = "Downloaded";
    updatePatchTable();
}

function applyPatch(index) {
    alert(`Applying Patch: ${patches[index].name}`);
    patches[index].status = "Applied";
    updatePatchTable();
}

function deletePatch(index) {
    patches.splice(index, 1);
    updatePatchTable();
}

function searchPatch() {
    let searchValue = document.getElementById('search').value.toLowerCase();
    let patchTable = document.getElementById('patchTable');
    patchTable.innerHTML = "";

    patches.filter((patch, index) =>
        patch.name.toLowerCase().includes(searchValue) ||
        patch.os.toLowerCase().includes(searchValue)
    ).forEach((patch, index) => {
        let row = `<tr>
            <td>${patch.name}</td>
            <td>${patch.version}</td>
            <td>${patch.os}</td>
            <td class="action-buttons">
                ${patch.status === "Pending" ? `
                    <button class="download" onclick="downloadPatch(${index})">Download</button>
                    <button class="apply" onclick="applyPatch(${index})">Apply</button>
                    <button class="delete" onclick="deletePatch(${index})">Delete</button>
                ` : `<span style="color: green;">${patch.status}</span>`}
            </td>
        </tr>`;
        patchTable.innerHTML += row;
    });
}


fetch('/get_patches')
    .then(response => response.json())
    .then(data => {
        console.log("Fetched Patches:", data); // Debugging
        displayPatches(data);
    })
    .catch(error => console.error('Error fetching patches:', error));

function displayPatches(data) {
    let table = document.getElementById("patchTable");
    if (!table) {
        console.error("patchTable not found!");
        return;
    }
    let tbody = table.getElementsByTagName("tbody")[0];
    tbody.innerHTML = "";

    data.forEach((patch, index) => {
        let row = `<tr>
            <td>${patch.file_name}</td>
            <td>${patch.patch_version}</td>
            <td>${patch.os_type}</td>
            <td>
                <a href="/download/${patch.id}">Download</a>
                <a href="/apply/${patch.id}">Apply</a>
                <a href="/delete/${patch.id}">Delete</a>
            </td>
        </tr>`;
        tbody.innerHTML += row;
    });
}

