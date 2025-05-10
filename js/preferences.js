/**
 * preferences.js - Client-side preference management using server API
 * Replaces cookies.js with server-side storage
 */

// Status indicator for API operations
function showStatus(message, isError = false) {
    const statusDiv = document.getElementById('status-message');
    if (!statusDiv) {
        // Create status div if it doesn't exist
        const newDiv = document.createElement('div');
        newDiv.id = 'status-message';
        newDiv.style.position = 'fixed';
        newDiv.style.bottom = '20px';
        newDiv.style.right = '20px';
        newDiv.style.padding = '10px';
        newDiv.style.borderRadius = '5px';
        newDiv.style.zIndex = '1000';
        document.body.appendChild(newDiv);
    }
    
    const div = document.getElementById('status-message');
    div.textContent = message;
    div.style.backgroundColor = isError ? '#f8d7da' : '#d1e7dd';
    div.style.color = isError ? '#721c24' : '#0f5132';
    div.style.display = 'block';
    
    // Hide after 3 seconds
    setTimeout(() => {
        div.style.display = 'none';
    }, 3000);
}

/**
 * Load preferences from the server API
 * @param {Function} callback - Called with preferences when loaded
 */
function loadPreferences(callback) {
    showStatus('Loading preferences...');
    
    fetch('/api/preferences')
        .then(response => {
            if (!response.ok) {
                throw new Error(`HTTP error ${response.status}`);
            }
            return response.json();
        })
        .then(data => {
            if (data.success) {
                callback(data.preferences || {});
                showStatus('Preferences loaded');
            } else {
                showStatus(`Error: ${data.error}`, true);
            }
        })
        .catch(error => {
            console.error('Error loading preferences:', error);
            showStatus('Failed to load preferences', true);
            callback({});
        });
}

/**
 * Save a single preference to the server
 * @param {string} key - Preference key
 * @param {string} value - Preference value
 * @param {Function} callback - Optional callback when complete
 */
function savePreference(key, value, callback) {
    if (!key) {
        showStatus('Error: No preference key specified', true);
        return;
    }
    
    showStatus('Saving preference...');
    
    fetch('/api/preferences', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({
            key: key,
            value: value
        })
    })
    .then(response => {
        if (!response.ok) {
            throw new Error(`HTTP error ${response.status}`);
        }
        return response.json();
    })
    .then(data => {
        if (data.success) {
            showStatus(`Preference saved: ${key}`);
            if (callback) callback(true);
        } else {
            showStatus(`Error: ${data.error}`, true);
            if (callback) callback(false);
        }
    })
    .catch(error => {
        console.error('Error saving preference:', error);
        showStatus('Failed to save preference', true);
        if (callback) callback(false);
    });
}

/**
 * Save multiple preferences to the server
 * @param {Object} preferences - Key/value map of preferences
 * @param {Function} callback - Optional callback when complete
 */
function savePreferences(preferences, callback) {
    if (!preferences || Object.keys(preferences).length === 0) {
        showStatus('Error: No preferences to save', true);
        return;
    }
    
    showStatus('Saving preferences...');
    
    fetch('/api/preferences', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({
            preferences: preferences
        })
    })
    .then(response => {
        if (!response.ok) {
            throw new Error(`HTTP error ${response.status}`);
        }
        return response.json();
    })
    .then(data => {
        if (data.success) {
            showStatus('Preferences saved');
            if (callback) callback(true);
        } else {
            showStatus(`Error: ${data.error}`, true);
            if (callback) callback(false);
        }
    })
    .catch(error => {
        console.error('Error saving preferences:', error);
        showStatus('Failed to save preferences', true);
        if (callback) callback(false);
    });
}

/**
 * Delete a preference
 * @param {string} key - Preference key to delete
 * @param {Function} callback - Optional callback when complete
 */
function deletePreference(key, callback) {
    if (!key) {
        showStatus('Error: No preference key specified', true);
        return;
    }
    
    showStatus('Deleting preference...');
    
    fetch(`/api/preferences?key=${encodeURIComponent(key)}`, {
        method: 'DELETE'
    })
    .then(response => {
        if (!response.ok) {
            throw new Error(`HTTP error ${response.status}`);
        }
        return response.json();
    })
    .then(data => {
        if (data.success) {
            showStatus(`Preference deleted: ${key}`);
            if (callback) callback(true);
        } else {
            showStatus(`Error: ${data.error}`, true);
            if (callback) callback(false);
        }
    })
    .catch(error => {
        console.error('Error deleting preference:', error);
        showStatus('Failed to delete preference', true);
        if (callback) callback(false);
    });
}

/**
 * Clear a form by unchecking all checkboxes
 * @param {string} containerName - ID of the container element
 */
function clearForm(containerName) {
    const container = document.querySelector('#' + containerName);
    if (!container) return;
    
    const checkboxes = container.querySelectorAll('input[type="checkbox"]');
    for (let i = 0; i < checkboxes.length; i++) {
        checkboxes[i].checked = false;
    }
}

/**
 * Select all checkboxes in a form
 * @param {string} containerName - ID of the container element
 */
function selectAll(containerName) {
    const container = document.querySelector('#' + containerName);
    if (!container) return;
    
    const checkboxes = container.querySelectorAll('input[type="checkbox"]');
    for (let i = 0; i < checkboxes.length; i++) {
        checkboxes[i].checked = true;
    }
}

/**
 * Save form data to preferences
 * @param {string} prefKey - Preference key to save under
 * @param {string} containerName - ID of the form container
 */
function saveForm(prefKey, containerName) {
    const container = document.querySelector('#' + containerName);
    if (!container) {
        showStatus(`Error: Container #${containerName} not found`, true);
        return;
    }
    
    let list = "";
    const checkboxes = container.querySelectorAll('input[type="checkbox"]');
    for (let i = 0; i < checkboxes.length; i++) {
        if (checkboxes[i].checked) {
            list += checkboxes[i].name + ',';
        }
    }
    
    // Remove trailing comma if present
    if (list.endsWith(',')) {
        list = list.slice(0, -1);
    }
    
    savePreference(prefKey, list, (success) => {
        if (success) {
            // Redirect if data-redirect attribute exists
            const redirectElem = container.closest('[data-redirect]');
            if (redirectElem) {
                const redirectUrl = redirectElem.getAttribute('data-redirect');
                if (redirectUrl) {
                    window.location.href = redirectUrl;
                }
            }
        }
    });
}

/**
 * Load form data from preferences
 * @param {string} prefKey - Preference key to load
 * @param {string} containerName - ID of the form container
 */
function loadForm(prefKey, containerName) {
    fetch(`/api/preferences?key=${encodeURIComponent(prefKey)}`)
        .then(response => {
            if (!response.ok) {
                if (response.status === 404) {
                    // Preference not found, which is OK
                    return null;
                }
                throw new Error(`HTTP error ${response.status}`);
            }
            return response.json();
        })
        .then(data => {
            if (!data || !data.success) return;
            
            const list = data.value;
            if (!list) return;
            
            const values = list.split(',');
            const container = document.querySelector('#' + containerName);
            if (!container) return;
            
            const checkboxes = container.querySelectorAll('input[type="checkbox"]');
            for (let i = 0; i < values.length; i++) {
                const value = values[i].trim();
                if (!value) continue;
                
                for (let j = 0; j < checkboxes.length; j++) {
                    if (checkboxes[j].name === value) {
                        checkboxes[j].checked = true;
                    }
                }
            }
        })
        .catch(error => {
            console.error(`Error loading form data for ${prefKey}:`, error);
        });
}

/**
 * Save radio button selection to preferences
 * @param {string} prefKey - Preference key to save under
 * @param {string} containerName - ID of the form container
 */
function saveRadio(prefKey, containerName) {
    const container = document.querySelector('#' + containerName);
    if (!container) return;
    
    let selectedValue = '';
    const radios = container.querySelectorAll('input[type="radio"]');
    for (let i = 0; i < radios.length; i++) {
        if (radios[i].checked) {
            selectedValue = radios[i].value;
            break;
        }
    }
    
    savePreference(prefKey, selectedValue);
}

/**
 * Load radio button selection from preferences
 * @param {string} prefKey - Preference key to load
 * @param {string} containerName - ID of the form container
 */
function loadRadio(prefKey, containerName) {
    fetch(`/api/preferences?key=${encodeURIComponent(prefKey)}`)
        .then(response => {
            if (!response.ok) {
                if (response.status === 404) {
                    // Preference not found, which is OK
                    return null;
                }
                throw new Error(`HTTP error ${response.status}`);
            }
            return response.json();
        })
        .then(data => {
            if (!data || !data.success) return;
            
            const value = data.value;
            if (!value) return;
            
            const container = document.querySelector('#' + containerName);
            if (!container) return;
            
            const radios = container.querySelectorAll('input[type="radio"]');
            for (let i = 0; i < radios.length; i++) {
                radios[i].checked = (radios[i].value === value);
            }
        })
        .catch(error => {
            console.error(`Error loading radio data for ${prefKey}:`, error);
        });
}

/**
 * Save dropdown selection to preferences
 * @param {string} prefKey - Preference key to save under
 * @param {string} selectId - ID of the select element
 */
function saveDropdown(prefKey, selectId) {
    const selectElement = document.getElementById(selectId);
    if (!selectElement) return;
    
    let selectedValue = '';
    for (let i = 0; i < selectElement.options.length; i++) {
        if (selectElement.options[i].selected && !selectElement.options[i].disabled) {
            selectedValue = selectElement.options[i].value;
            break;
        }
    }
    
    savePreference(prefKey, selectedValue);
}

/**
 * Load dropdown selection from preferences
 * @param {string} prefKey - Preference key to load
 * @param {string} selectId - ID of the select element
 */
function loadDropdown(prefKey, selectId) {
    fetch(`/api/preferences?key=${encodeURIComponent(prefKey)}`)
        .then(response => {
            if (!response.ok) {
                if (response.status === 404) {
                    // Preference not found, which is OK
                    return null;
                }
                throw new Error(`HTTP error ${response.status}`);
            }
            return response.json();
        })
        .then(data => {
            if (!data || !data.success) return;
            
            const value = data.value;
            if (!value) return;
            
            const selectElement = document.getElementById(selectId);
            if (!selectElement) return;
            
            for (let i = 0; i < selectElement.options.length; i++) {
                selectElement.options[i].selected = (selectElement.options[i].value === value);
            }
        })
        .catch(error => {
            console.error(`Error loading dropdown data for ${prefKey}:`, error);
        });
}
