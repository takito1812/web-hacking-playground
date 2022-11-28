$('.alert').hide();
const form = document.querySelector('form');
form.addEventListener('submit', async (e) => {
  e.preventDefault();
  const username = document.querySelector('#username').value;
  const password = document.querySelector('#password').value;
  const response = await fetch('/login', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      username,
      password,
    }),
  });
  const data = await response.json();
  if (data.token) {
    localStorage.setItem('token', data.token);
    window.location.href = '/';
  } else {
    $('.alert').show().text(data.error);
    setTimeout(() => {
      $('.alert').hide();
    }, 3000);
  }
});
