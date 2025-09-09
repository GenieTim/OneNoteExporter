const OneNoteDiaryExport = require('./onenote-diary-export');
/**
 * Using OneNoteDiaryExport in browser context
 */
const exporter = new OneNoteDiaryExport(console);

function submitForm() {
  const options = {
    'noteBookId': false,
    'pages': false,
    'sectionId': false
  };
  const notebookVal = document.querySelector('input[name=notebook]').value;
  const sectionVal = document.querySelector('input[name=section]').value;
  const pagesVal = document.querySelector('input[name=pages]').value;
  if (notebookVal.trim()) {
    options.noteBookId = notebookVal.trim();
  }
  if (sectionVal.trim()) {
    options.sectionId = sectionVal.trim();
  }
  if (pagesVal.trim()) {
    options.pages = pagesVal.trim();
  }

  console.log('Starting exporter with options', options);
  exporter.run(options);
}

window.addEventListener('load', () => {
  const btn = document.querySelector('button[name=submitBtn]');
  btn.addEventListener('click', e => {
    e.preventDefault();
    submitForm();
  });
});
