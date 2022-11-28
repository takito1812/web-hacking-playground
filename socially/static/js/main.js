if (localStorage.getItem('token') && !document.cookie.match(/^(.*;)?\s*session\s*=\s*[^;]+(.*)?$/)) {
  $.ajax({
    url: '/session',
    type: 'GET',
    headers: {
      Authorization: `Bearer ${localStorage.getItem('token')}`,
    },
    success() {
      window.location.reload();
    },
  });
}
