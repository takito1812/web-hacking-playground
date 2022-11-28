$('.alert').hide();

if (!localStorage.getItem('token')) {
  window.location.href = '/';
}

function otpNotVerified(data) {
  if (data.error === 'OTP not verified') {
    $('#verifyOtp').modal('show');
    $('#verifyOtp .modal-body').html('<iframe src="/verifyotp" width="100%" height="100%" frameborder="0"></iframe>');
  }
}

const smtpServerSettingsForm = document.getElementById('smtpServerSettings');
smtpServerSettingsForm.addEventListener('submit', async (e) => {
  e.preventDefault();
  const smtpServer = document.querySelector('#smtpServer').value;
  const response = await fetch('/updatesmtp', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${localStorage.getItem('token')}`,
    },
    body: JSON.stringify({
      smtpServer,
    }),
  });
  const data = await response.json();
  if (data.success) {
    window.location.reload();
  } else {
    $('.alert').show().text(data.error);
    otpNotVerified(data);
    setTimeout(() => {
      $('.alert').hide();
    }, 3000);
  }
});

const sendTestEmailForm = document.getElementById('sendTestEmail');
sendTestEmailForm.addEventListener('submit', async (e) => {
  e.preventDefault();
  const to = document.querySelector('#to').value;
  const message = document.querySelector('#message').value;
  const response = await fetch('/sendemail', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${localStorage.getItem('token')}`,
    },
    body: JSON.stringify({
      to,
      message,
    }),
  });
  const data = await response.json();
  if (data.success) {
    window.location.reload();
  } else {
    $('.alert').show().text(data.error);
    otpNotVerified(data);
    setTimeout(() => {
      $('.alert').hide();
    }, 3000);
  }
});
