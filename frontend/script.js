<<<<<<< HEAD
let token = null;

// Kayıt işlemi
async function register() {
=======
let token = '';

function register() {
>>>>>>> 377f31e7ee60d20dd41dd79ba7ebf58e69ec96a5
  const username = document.getElementById('reg_username').value;
  const email = document.getElementById('reg_email').value;
  const password = document.getElementById('reg_password').value;

<<<<<<< HEAD
  const response = await fetch('http://192.168.68.71:5004/register', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({ username, email, password }),
  });

  const data = await response.json();
  if (response.ok) {
    document.getElementById('registerMessage').textContent = 'Registration successful!';
  } else {
    document.getElementById('registerMessage').textContent = data.message || 'Registration failed!';
  }
}

// Giriş işlemi
async function login() {
  const username = document.getElementById('login_username').value;
  const password = document.getElementById('login_password').value;

  const response = await fetch('http://192.168.68.71:5004/login', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({ username, password }),
  });

  const data = await response.json();
  if (response.ok) {
    token = data.token;
    document.getElementById('loginMessage').textContent = 'Login successful!';
  } else {
    document.getElementById('loginMessage').textContent = data.message || 'Login failed!';
  }
}

// Profil bilgilerini getirme
async function fetchProfile() {
  if (!token) {
    alert('Please login first!');
    return;
  }

  const response = await fetch('http://192.168.68.71:5004/profile', {
    method: 'GET',
    headers: {
      'Authorization': `Bearer ${token}`,
    },
  });

  const data = await response.json();
  if (response.ok) {
    document.getElementById('profile').innerHTML = `
      <p>User ID: ${data.user_id}</p>
      <p>Role: ${data.role}</p>
      <p>Message: ${data.message}</p>
    `;
  } else {
    document.getElementById('profile').textContent = data.message || 'Failed to fetch profile!';
  }
}

// Etkinlik listesini getirme
async function fetchEvents() {
  if (!token) {
    alert('Please login first!');
    return;
  }

  const response = await fetch('http://192.168.68.71:5004/events', {
    method: 'GET',
    headers: {
      'Authorization': `Bearer ${token}`,
    },
  });

  const data = await response.json();
  if (response.ok) {
    const eventList = document.getElementById('eventList');
    eventList.innerHTML = '';
    data.forEach(event => {
      const li = document.createElement('li');
      li.textContent = `${event.name} - ${event.description} (${event.date_time})`;
      eventList.appendChild(li);
    });
  } else {
    document.getElementById('eventList').textContent = data.message || 'Failed to fetch events!';
  }
}
=======
  fetch('http://192.168.1.6:5004/register', {  // Kendi IP adresin
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username, email, password })
  })
  .then(response => response.json())
  .then(data => {
    alert(data.message);
  })
  .catch(error => console.error('Error:', error));
}

function login() {
  const username = document.getElementById('username').value;
  const password = document.getElementById('password').value;

  fetch('http://192.168.1.6:5004/login', {  // Kendi IP adresin
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username, password })
  })
  .then(response => response.json())
  .then(data => {
    if (data.token) {
      token = data.token;
      alert('Login successful!');
    } else {
      alert('Login failed');
    }
  })
  .catch(error => console.error('Error:', error));
}

function fetchEvents() {
  fetch('http://192.168.1.6:5004/events', {  // Kendi IP adresin
    method: 'GET',
    headers: { 'Authorization': `Bearer ${token}` }
  })
  .then(response => response.json())
  .then(events => {
    const eventList = document.getElementById('eventList');
    eventList.innerHTML = '';
    events.forEach(event => {
      const li = document.createElement('li');
      li.textContent = `${event.name} - ${event.date_time}`;
      eventList.appendChild(li);
    });
  });
}
>>>>>>> 377f31e7ee60d20dd41dd79ba7ebf58e69ec96a5
