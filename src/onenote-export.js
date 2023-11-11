let MsGraph = require('./ms-graph-utility')
const asyncForEach = require('./async-foreach')

/**
 * Must not be a command as it requires a browser :|
 * Generate by
 * `browserify src/onenote-diary-export.js > src/onenote-diary-export.bundle.js`
 */
class OneNoteDiaryExport {
  constructor(logger) {
    this.logger = logger
  }

  async run(flags) {
    this.serviceRootUrl = 'https://graph.microsoft.com/v1.0/me/onenote/'
    this.msApi = new MsGraph(this.logger)
    const {noteBookId, sectionId, pages} = flags
    if (pages) {
      // All set. load & process data
      const text = await this.loadContentFromOneNote(noteBookId, sectionId, pages)
      this.log(text)

      let target = document.getElementById('target')
      target.innerText = text;
      let today = new Date()
      target.appendChild(this.getFileDownloadLink(`onenote-export-${today.getDate()}-${today.getMonth()}-${today.getFullYear()}.html`, text))
      // Fs.writeFileSync('../../diary-export.html', text)
    } else if (noteBookId && sectionId) {
      await this.listPagesFromOneNote(noteBookId, sectionId)
    } else if (noteBookId) {
      await this.listSectionsFromOneNote(noteBookId)
    } else {
      await this.listNoteBooksFromOneNote()
    }
  }


  /**
   * List all available notebooks of the connected OneNote account
   *
   * @returns {array} list of books
   */
  async listNoteBooksFromOneNote() {
    let books = await this.msApi.makeGetRequest(`${this.serviceRootUrl}notebooks`)
    this.log('Please specify a notebook id with "-n". Following ids are available:')
    this.log('Id\tTitle')
    this.log(books.value)
    books.value.forEach(book => {
      this.log(`${book.id}\t${book.displayName}`)
    })

    return books
  }

  async searchBookIdsFromOneNote(bookFilter) {
    let ids = [];
    let books = [];
    if (!bookFilter) {
      books = await this.msApi.makeGetRequest(`${this.serviceRootUrl}notebooks`)
      books = books.value
    } else if (this.isOneNoteId(bookFilter)) {
      ids.push(bookFilter)
    } else {
      books = await this.msApi.makeGetRequest(`${this.serviceRootUrl}notebooks?$filter=startswith(displayName, '${encodeURI(bookFilter)}')`)
      books = books.value
    }
    books.forEach(section => {
      ids.push(section.id)
    });

    return ids
  }

  /**
   * List all available sections in a certain notebook
   *
   * @param {string} noteBookId the OneNote id of the Notebook or a string the book name starts with
   * @returns {array} sections
   */
  async listSectionsFromOneNote(noteBookId) {
    let sections = await this.msApi.makeGetRequest(`${this.serviceRootUrl}notebooks/${noteBookId}/sections`)
    this.log('Please specify a section with "-s". Following ids are available:')
    this.log('Id\tTitle')
    this.log(sections)
    sections.value.forEach(section => {
      this.log(`${section.id}\t${section.displayName}`)
    })

    return sections
  }

  async searchSectionIdsFromOneNote(noteBookId, sectionFilter) {
    let ids = []
    let books = await this.searchBookIdsFromOneNote(noteBookId)
    await asyncForEach(books, async bookId => {
      let sections = []
      if (!sectionFilter) {
        // Test
        sections = await this.msApi.makeGetRequest(`${this.serviceRootUrl}notebooks/${bookId}/sections`)
        sections = sections.value
      } else if (this.isOneNoteId(sectionFilter)) {
        ids.push(sectionFilter)
      } else {
        sections = await this.msApi.makeGetRequest(`${this.serviceRootUrl}notebooks/${bookId}/sections?$filter=startswith(displayName, '${encodeURI(sectionFilter)}')`)
        sections = sections.value
      }

      sections.forEach(section => {
        ids.push(section.id)
      })
    })

    return ids;
  }

  /**
   * List all available pages in a certain section
   *
   * @param {string} noteBookId the OneNote id of the Notebook or a string the book name starts with
   * @param {string} sectionId the OneNote id of the Section, or a search string to search a section for
   * @returns {array} pages
   */
  async listPagesFromOneNote(noteBookId, sectionId) {
    if (!this.isOneNoteId(sectionId)) {
      let sections = await this.searchSectionIdsFromOneNote(noteBookId, sectionId);
      // Optinionated: choose first result
      // eslint-disable-next-line prefer-destructuring
      sectionId = sections[0]
    }
    let pages = await this.msApi.makeGetRequest(`${this.serviceRootUrl}sections/${sectionId}/pages`)
    this.log('Please specify pages with "-p". Following ids are available:')
    this.log('Id\tTitle')
    this.log(pages)
    pages.value.forEach(page => {
      this.log(`${page.id}\t${page.title}`)
    })

    return pages
  }

  async searchPageIdsFromOneNote(noteBookId, sectionId, pageSearch) {
    if (this.isOneNoteId(pageSearch)) {
      return [pageSearch]
    }
    let sections = await this.searchSectionIdsFromOneNote(noteBookId, sectionId)
    let pageIds = []
    await asyncForEach(sections, async sectionId => {
      let page = await this.msApi.makeGetRequest(`${this.serviceRootUrl}sections/${sectionId}/pages?$filter=startswith(title, '${encodeURI(pageSearch)}')&$orderby=title`)
      page.value.forEach(page => {
        pageIds.push(page.id)
      })
    })

    return pageIds
  }

  /**
   * Get the concatenated HTML from all pages
   *
   * @param {string} noteBookId the OneNote id of the Notebook
   * @param {string} sectionId the OneNote id of the Section, or a search string to search a Section for
   * @param {array|string} pages the OneNote ids of the pages to fetch or a search string to search a Page for
   * @returns {string} the HTML content of all the pages
   */
  async loadContentFromOneNote(noteBookId, sectionId, pages) {
    if (typeof pages === 'string' || pages instanceof String) {
      pages = await this.searchPageIdsFromOneNote(noteBookId, sectionId, pages)
    }
    let text = '<!Doctype html><html><body>'
    let domparser = new DOMParser()
    await asyncForEach(pages, async page => {
      let pageContent = await this.msApi.makeGetRequest(`${this.serviceRootUrl}pages/${page}/content`, true)
      this.log(pageContent)
      let doc = domparser.parseFromString(pageContent, 'text/html')
      try {
        text += `<h1>${doc.querySelector('title').innerText}<h1>`
      } catch (e) {
        this.log(`Failed setting title: ${e}`)
      }
      text += doc.body.innerHTML;
    })
    text += '</body></html>';

    return text
  }

  /**
   * Very basic test to check whether a given string is a OneNote id.
   * Does not hold up to nearly anything; except my personal OneNote notes are covered.
   *
   * @param {string} test the string to test
   *@returns {boolean} whether the test string could be a OneNote id
   */
  isOneNoteId(test) {
    let indexOfFail = -1

    return (typeof test === 'string' || test instanceof String) && test.startsWith('0-') && test.indexOf('!') !== indexOfFail
  }

  getFileDownloadLink(filename, text) {
    let element = document.createElement('a')
    element.setAttribute('href', `data:text/plain;charset=utf-8,${encodeURIComponent(text)}`)
    element.setAttribute('download', filename)

    element.style.display = 'none'

    return element
  }


  log(text) {
    try {
      if (this.logger) {
        this.logger.log(text)
      }
    } catch (ex) {
      try {
        console.error(ex)
      } catch (e) {
        // Do nothing?!?
      }
    }
  }
}

module.exports = OneNoteDiaryExport

