let token = '';

function register() {
  const username = document.getElementById('reg_username').value;
  const email = document.getElementById('reg_email').value;
  const password = document.getElementById('reg_password').value;

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
