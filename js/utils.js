function formSubmissionIntercept() {
    const form = document.getElementById('searchform');
    if (!form) {
        //console.log("Form not found, skipping interception");
        return;
    }
    form.addEventListener('submit', function(event) {
        //event.preventDefault();
        const searchInput = document.getElementById('searchbox');
        if (searchInput) {
            const trimmedSearchValue = searchInput.value.trim();
            const hasSearchMode = trimmedSearchValue.includes('sm:');

            if (!hasSearchMode) {
                const selectedRadio = document.querySelector('input[name="search_mode"]:checked');
                if (selectedRadio) {
                    searchInput.value = selectedRadio.value + trimmedSearchValue;
                } else {
                    //console.log('radio not found');
                    return;
                }
            }
        } else { 
            //console.log('input not found');
            return;
        }
    });
}

document.addEventListener('DOMContentLoaded', formSubmissionIntercept);