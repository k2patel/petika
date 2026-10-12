try {
  const value = localStorage.getItem('petika-theme');
  if (['light', 'dark', 'system'].includes(value)) document.documentElement.dataset.theme = value;
} catch {
  /* System theme works without storage. */ }
