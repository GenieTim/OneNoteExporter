const fs = require('fs')
const puppeteer = require('puppeteer')
const { cli } = require('cli-ux')
const crypto = require("crypto");

class InteractiveExporter {
  async run() {
    this.logger = console;
    await this.initializeBrowser()
    this.driver.goto("https://onenote.com")
    this.logger.log("Login & navigate to the OneNote page to download.")
    let addDownload = true;
    while (addDownload) {
      addDownload = await cli.confirm("Ready to download the current page? (y/n)")
      await this.downloadCurrentPage()
    }
    this.logger.log("Done. Thank you for using the InteractiveExporter.")
  }

  /**
   * Download the content frame of the OneNote page to a file
   * 
   * @returns {void} void
   */
  async downloadCurrentPage() {
    const contentFrame = this.driver.frames().find(frame => frame.name() === 'WebApplicationFrame')
    if (!contentFrame) {
      this.logger.error("Did not find frame.")
    }
    const content = await contentFrame.$("#WACDocumentPanel.EditMode")
    const title = await content.$eval("#PageContentContainer .Title .TitleOutline", e => e.innerText)
    const saveTitle = title.replace(/[^a-z0-9]/gi, '_').toLowerCase()
    const saveEnding = crypto.randomBytes(8).toString("hex")
    const filename = `${saveTitle}${saveEnding}.html`;
    await fs.writeFile(filename, await content.evaluate(node => node.innerHTML), { "encoding": "utf8" }, err => {
      if (err) {
        this.logger.error(err)
      }
      this.logger.info(`Wrote file "${filename}"`)
    })
  }

  /**
   * Set up the browser
   * 
   * @returns {void} void
   */
  async initializeBrowser() {
    this.browser = await puppeteer.launch({
      "headless": false,
      "userDataDir": './user_data'
    })
    await this.openNewPage()
  }

  /**
   * Open a new page/tab
   * 
   * @returns {void} void
   */
  async openNewPage() {
    try {
      this.driver = await this.browser.newPage()
    } catch (error) {
      this.logger.error(error)

      return
    }
    this.driver.setViewport({
      "height": 0,
      "width": 0
    })
  }
}

let iE = new InteractiveExporter();
iE.run();
