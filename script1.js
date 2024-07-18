/*
  
    const data = await response.json();
    if (response.ok) {
      alert(data);
      // Store the token and redirect based on user
      localStorage.setItem('token', data.token);
      if (email === 'khyatin2003@gmail.com') {
        window.location.href = 'page1.html';
      } else if (email === 'mkvivek26@gmail.com') {
        window.location.href = 'page2.html';
      } else {
        // Redirect to a default page for other users
        window.location.href = 'default.html';
      }
    } else {
      alert(data.message);
    }
  });
  */

document.getElementById('login-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const email = document.getElementById('email').value;
  const password = document.getElementById('password').value;
  const role = document.getElementById('role').value; // Get the selected role

  console.log(email);
  console.log(password);
  console.log(role); // Log the selected role

  const response = await fetch('http://localhost:3000/login', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({ email, password, role }), // Include the role in the request body
  });

  const data = await response.json();
  if (response.ok) {
    alert(data);
    // Store the token and redirect based on user and role
    localStorage.setItem('token', data.token);
    if (role === 'admin') {
      window.location.href = 'page1.html'; // Redirect to admin dashboard
    } else if (role === 'user') {
      window.location.href = 'page2.html'; // Redirect to user dashboard
    } else {
      // Handle invalid role
      alert('Invalid role selected');
    }
  } else {
    alert(data.message);
  }
});


  document.getElementById('contact-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    const name = document.getElementById('name').value;
    const email = document.getElementById('email').value;
    const message = document.getElementById('message').value;
  
    const response = await fetch('http://localhost:3000/register', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ name, email, message }),
    });
  
    const data = await response.json();
    if (response.ok) {
      alert('Message sent successfully!');
    } else {
      alert(data.message);
    }
  })
  




  