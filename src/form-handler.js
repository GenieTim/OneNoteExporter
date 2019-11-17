let OneNoteDiaryExport = require('./onenote-diary-export')
/**
 * Using OneNoteDiaryExport in browser context
 */
let exporter = new OneNoteDiaryExport(console)

function submitForm() {
  let options = {
    "noteBookId": false,
    "pages": false,
    "sectionId": false
  };
  let notebookVal = document.querySelector("input[name=notebook]").value
  let sectionVal = document.querySelector("input[name=section]").value
  let pagesVal = document.querySelector("input[name=pages]").value
  if (notebookVal.trim()) {
    options.noteBookId = notebookVal.trim()
  }
  if (sectionVal.trim()) {
    options.sectionId = sectionVal.trim()
  }
  if (pagesVal.trim()) {
    options.pages = pagesVal.trim()
  }

  console.log("Starting exporter with options", options)
  exporter.run(options)
}

window.addEventListener('load', () => {
  let btn = document.querySelector("button[name=submitBtn]")
  btn.addEventListener('click', e => {
    e.preventDefault()
    submitForm()
  })
})
