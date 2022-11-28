const form = document.querySelector('form');
form.addEventListener('submit', async (e) => {
  e.preventDefault();
  const post = document.querySelector('#post').value;
  const response = await fetch('/post', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      post,
    }),
  });
  const data = await response.json();
  if (data.success) {
    window.location.href = '/';
  } else {
    $('.alert').show().text(data.error);
    setTimeout(() => {
      $('.alert').hide();
    }, 3000);
  }
});
