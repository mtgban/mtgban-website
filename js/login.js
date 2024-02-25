var firebaseConfig = {
    apiKey: "AIzaSyA3NJHS3hDkXyw0TFuBsGWB6A4o8PghimQ",
    authDomain: "ban-on-fire.firebaseapp.com",
    projectId: "ban-on-fire",
    storageBucket: "ban-on-fire.appspot.com",
    messagingSenderId: "500521386178",
    appId: "1:500521386178:web:8bfb5f9032c040a162bb5b",
};

firebase.initializeApp(firebaseConfig);

var ui = new firebaseui.auth.AuthUI(firebase.auth());

function startFirebaseUI() {
    var uiConfig = {
        signInSuccessUrl: '/search',
        signInOptions: [
            firebase.auth.EmailAuthProvider.PROVIDER_ID,
            firebase.auth.GoogleAuthProvider.PROVIDER_ID,
        ],
    };
    ui.start('#firebaseui-auth-container', uiConfig);
}

var auth = firebase.auth();

// Function to close the modal
function closeModal() {
    document.getElementById('authModal').style.display = 'none';
}

// Event listener for the button
document.getElementById('startAuthButton').addEventListener('click', function () {
    // Show the modal
    document.getElementById('authModal').style.display = 'block';
    // Start FirebaseUI
    startFirebaseUI();
});

// Listen for auth state changes
auth.onAuthStateChanged(async (user) => {
    if (user) {
        console.log('User is signed in:', user);
        try {
            const idToken = await user.getIdToken();
            submitTokenToServer(idToken);
        } catch (error) {
            console.error('Error getting ID token: ', error);
        }
    } else {
        console.log('User is signed out.');
    }
});

// Submits token to server
function submitTokenToServer(idToken) {
    const formData = new FormData();
    formData.append('idToken', idToken);

    fetch('/verify-token', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({ idToken: idToken })
    })
        .then(response => response.text())  // Get the response as text
        .then(text => {
            try {
                // Try to parse the response as JSON
                return JSON.parse(text);
            } catch (error) {
                // If the response is not valid JSON, throw an error
                throw new Error('Bad response from server');
            }
        })
        .then(data => handleServerResponse(data))
        .catch(error => console.error('Token verification error: ', error));

    function handleServerResponse(data) {
        console.log('Token verification response: ', data);
        if (data.status === 'success') {
            alert('User has logged in. Redirecting to search page...');
            window.location.href = '/search';
        } else {
            alert('Please try logging in again.');
            window.location.href = '/login';
        }
    }
}