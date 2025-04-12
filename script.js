function handleRegister(event) {
    event.preventDefault();

    const form = document.getElementById("register");
    const formData = new FormData(form);

    fetch("/register", {
        method: "POST",
        body: formData
    })
    .then(res => res.json())
    .then(data => {
        if (data.success) {
            // ✅ SweetAlert with auto timer and redirect after it closes
            Swal.fire({
                icon: 'success',
                title: 'Registered!',
                text: 'You have been registered successfully.',
                timer: 2000,
                showConfirmButton: false,
                timerProgressBar: true,
                didClose: () => {
                    window.location.href = "/login"; // ✅ redirect after popup closes
                }
            });

            form.reset();
        } else {
            Swal.fire({
                icon: 'error',
                title: 'Registration Failed',
                text: data.message || 'Something went wrong.',
                confirmButtonText: 'Try Again'
            });
        }
    })
    .catch(error => {
        console.error('Error:', error);
        Swal.fire({
            icon: 'error',
            title: 'Server Error',
            text: 'Unable to process request.',
        });
    });
}
