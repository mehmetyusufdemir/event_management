let token = null;
const API_URL = "http://192.168.1.15:5004";  // Doğru IP adresini buraya gir

// Sayfa yüklendiğinde chatbot bölümünü gizle
document.addEventListener('DOMContentLoaded', function() {
  document.getElementById('chatbot-section').style.display = 'none';
});

// Kayıt işlemi
async function register() {
  const username = document.getElementById('reg_username').value;
  const email = document.getElementById('reg_email').value;
  const password = document.getElementById('reg_password').value;

  try {
    const response = await fetch(`${API_URL}/register`, {
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
  } catch (error) {
    document.getElementById('registerMessage').textContent = `Network error: ${error.message}`;
  }
}

// Giriş işlemi
async function login() {
  const username = document.getElementById('login_username').value;
  const password = document.getElementById('login_password').value;

  try {
    const response = await fetch(`${API_URL}/login`, {
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
      // Kullanıcı giriş yaptıktan sonra chatbot bölümünü göster
      document.getElementById('chatbot-section').style.display = 'block';

      // Hoş geldin mesajı ekle
      addMessageToChat('bot-message', 'Hoş geldiniz! Etkinlikler hakkında bana soru sorabilirsiniz.');
    } else {
      document.getElementById('loginMessage').textContent = data.message || 'Login failed!';
    }
  } catch (error) {
    document.getElementById('loginMessage').textContent = `Network error: ${error.message}`;
  }
}

// Profil bilgilerini getirme
async function fetchProfile() {
  if (!token) {
    alert('Please login first!');
    return;
  }

  try {
    const response = await fetch(`${API_URL}/profile`, {
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
  } catch (error) {
    document.getElementById('profile').textContent = `Network error: ${error.message}`;
  }
}

// Etkinlik listesini getirme
async function fetchEvents() {
  if (!token) {
    alert('Please login first!');
    return;
  }

  try {
    const response = await fetch(`${API_URL}/events`, {
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
  } catch (error) {
    document.getElementById('eventList').textContent = `Network error: ${error.message}`;
  }
}

async function sendChatMessage() {
  if (!token) {
    alert('Lütfen önce giriş yapın!');
    return;
  }

  const chatInput = document.getElementById('chat-input');
  const query = chatInput.value.trim();

  if (!query) return;

  // Kullanıcı mesajını ekrana ekle
  addMessageToChat('user-message', query);

  // Yanıt beklendiğini göster
  const waitingMessage = "Yanıt bekleniyor...";
  const waitingMessageId = addMessageToChat('bot-message', waitingMessage);

  try {
    console.log("Sending query to API:", query);

    const response = await fetch(`${API_URL}/chat`, {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${token}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ query }),
    });

    // Bekleme mesajını kaldır
    removeMessage(waitingMessageId);

    // JSON yanıtını al
    const data = await response.json();
    console.log("Response data:", data);

    if (!response.ok) {
      // Server tarafındaki hatayı göster
      addMessageToChat('bot-message', `Sunucu hatası: ${data.message || response.statusText}`);
      return;
    }

    // "No results found" durumunu ele al
    if (data.message === 'No results found') {
      addMessageToChat('bot-message', 'Bu sorgu için sonuç bulunamadı.');
      return;
    }

    if (data.response) {
      // Sonuçları göster
      if (Array.isArray(data.response) && data.response.length > 0) {
        // Tablo başlıklarını al
        const headers = Object.keys(data.response[0]);

        // HTML tablosu oluştur
        let tableHTML = "<table border='1' style='border-collapse: collapse; width: 100%;'>";

        // Tablo başlığı
        tableHTML += "<thead><tr>";
        headers.forEach(header => {
          tableHTML += `<th style='padding: 8px; text-align: left;'>${header}</th>`;
        });
        tableHTML += "</tr></thead>";

        // Tablo verisi
        tableHTML += "<tbody>";
        data.response.forEach(row => {
          tableHTML += "<tr>";
          headers.forEach(header => {
            tableHTML += `<td style='padding: 8px;'>${row[header] || ''}</td>`;
          });
          tableHTML += "</tr>";
        });
        tableHTML += "</tbody></table>";

        addMessageToChat('bot-message', tableHTML);
      } else {
        addMessageToChat('bot-message', 'Sorgu başarılı, ancak görüntülenecek veri yok.');
      }
    } else {
      addMessageToChat('bot-message', 'Geçersiz yanıt format.');
    }
  } catch (error) {
    // Bekleme mesajını kaldır (eğer hala varsa)
    removeMessage(waitingMessageId);

    console.error("Ağ hatası:", error);
    addMessageToChat('bot-message', `Bir hata oluştu: ${error.message}`);
  }

  // Input alanını temizle
  chatInput.value = '';
}


// Sohbet mesajını ekrana ekle ve mesaj ID'sini döndür
function addMessageToChat(messageType, messageText) {
  const chatContainer = document.getElementById('chat-messages');
  const messageElement = document.createElement('div');
  const messageId = 'msg-' + Date.now();

  messageElement.id = messageId;
  messageElement.className = `chat-message ${messageType}`;
  messageElement.innerHTML = messageText.replace(/\n/g, "<br>"); // SQL formatı için satır sonlarını koru
  chatContainer.appendChild(messageElement);

  // Mesaj listesini en aşağı kaydır
  chatContainer.scrollTop = chatContainer.scrollHeight;

  return messageId;
}

// Mesajı ID ile kaldır
function removeMessage(messageId) {
  const messageElement = document.getElementById(messageId);
  if (messageElement) {
    messageElement.remove();
  }
}

// Enter tuşuna basıldığında mesaj gönderme
document.addEventListener('DOMContentLoaded', function() {
  const chatInput = document.getElementById('chat-input');
  chatInput.addEventListener('keypress', function(e) {
    if (e.key === 'Enter') {
      sendChatMessage();
    }
  });
});