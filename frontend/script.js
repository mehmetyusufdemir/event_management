let token = null;

// Kayıt işlemi
async function register() {
  const username = document.getElementById('reg_username').value;
  const email = document.getElementById('reg_email').value;
  const password = document.getElementById('reg_password').value;

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