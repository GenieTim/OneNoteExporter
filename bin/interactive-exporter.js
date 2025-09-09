const fs = require('fs').promises;
const path = require('path');
const puppeteer = require('puppeteer');
const {cli} = require('cli-ux');
const crypto = require('crypto');
const cheerio = require('cheerio');

// Constants
const RANDOM_BYTES_LENGTH = 8;
const EXIT_SUCCESS = 0;
const WAIT_TIME_MS = 1000;
const ARGS_SLICE_INDEX = 2;

const SELECTORS = {
  CONTENT_FRAME: 'WebApplicationFrame',
  PAGE_CONTENT: '#WACDocumentPanelContent',
  PAGE_TITLE: '#PageContentContainer .Title .TitleOutline',
  PAGES_IN_SECTION: '#NavPane #PageList .pageNode content',
  SECTIONS_IN_NOTEBOOK: '#NavPane #NavPaneSectionList .sectionList .sectionItem content',
  SECTION_GROUPS: '#NavPane #NavPaneSectionList [role="treeitem"]'
};

// Download modes
const DOWNLOAD_MODES = {
  NOTEBOOK: 'notebook',
  PAGE: 'page',
  SECTION: 'section'
};

class InteractiveExporter {
  constructor() {
    this.logger = console;
    this.downloadMode = this.parseArguments();
    this.currentSectionFolder = null;
  }

  /**
   * Parse command line arguments
   * @returns {string} The download mode
   */
  parseArguments() {
    const args = process.argv.slice(ARGS_SLICE_INDEX);
    const modeFlags = {
      '--notebook': DOWNLOAD_MODES.NOTEBOOK,
      '--page': DOWNLOAD_MODES.PAGE,
      '--section': DOWNLOAD_MODES.SECTION,
      '-n': DOWNLOAD_MODES.NOTEBOOK,
      '-p': DOWNLOAD_MODES.PAGE,
      '-s': DOWNLOAD_MODES.SECTION
    };

    // Check for help flag
    if (args.includes('--help') || args.includes('-h')) {
      this.showHelp();
      process.exit(EXIT_SUCCESS);
    }

    // Find the download mode
    const modeFlag = args.find(arg => Object.keys(modeFlags).includes(arg));
    if (modeFlag) {
      return modeFlags[modeFlag];
    }

    // Default to page mode
    return DOWNLOAD_MODES.PAGE;
  }

  /**
   * Show help message
   */
  showHelp() {
    this.logger.log(`
OneNote Interactive Exporter

Usage: node interactive-exporter.js [OPTIONS]

Options:
  -p, --page      Download current page only (default)
  -s, --section   Download all pages in current section
  -n, --notebook  Download entire notebook (all sections and pages)
  -h, --help      Show this help message

Examples:
  node interactive-exporter.js --page
  node interactive-exporter.js -s
  node interactive-exporter.js --notebook
    `);
  }

  /**
   * Main execution method
   * @returns {Promise<number>} Exit code
   */
  async run() {
    this.logger.log(`Starting OneNote Exporter in ${this.downloadMode} mode...`);

    await this.initializeBrowser();
    await this.driver.goto('https://onenote.com');

    this.logger.log('Please login & navigate to the OneNote page/section/notebook to download.');
    const ready = await cli.confirm(`Ready to download ${this.downloadMode}? (y/n)`);

    if (!ready) {
      this.logger.log('Export cancelled.');
      await this.cleanup();
      return EXIT_SUCCESS;
    }

    try {
      switch (this.downloadMode) {
      case DOWNLOAD_MODES.PAGE:
        await this.downloadCurrentPage();
        break;
      case DOWNLOAD_MODES.SECTION:
        await this.downloadCurrentSection();
        break;
      case DOWNLOAD_MODES.NOTEBOOK:
        await this.downloadCurrentNotebook();
        break;
      default:
        throw new Error(`Unknown download mode: ${this.downloadMode}`);
      }
    } catch (error) {
      this.logger.error('Error during download:', error.message);
    }

    this.logger.log('Done. Thank you for using the InteractiveExporter.');
    await this.cleanup();
    return EXIT_SUCCESS;
  }

  /**
   * Download all pages in the current section
   */
  async downloadCurrentSection() {
    this.logger.log('Downloading all pages in current section...');

    const pageElements = await this.driver.$$(SELECTORS.PAGES_IN_SECTION);
    if (pageElements.length === 0) {
      this.logger.warn('No pages found in current section.');
      return;
    }

    this.logger.log(`Found ${pageElements.length} pages in section.`);

    for (let i = 0; i < pageElements.length; i++) {
      try {
        this.logger.log(`Downloading page ${i + 1}/${pageElements.length}...`);

        // Click on the page to navigate to it
        const pageElement = await this.driver.$$(SELECTORS.PAGES_IN_SECTION);
        if (pageElement[i]) {
          await pageElement[i].click();
          await this.waitForPageLoad();
          await this.downloadCurrentPage();
        }
      } catch (error) {
        this.logger.error(`Error downloading page ${i + 1}:`, error.message);
      }
    }
  }

  /**
   * Download entire notebook (all sections and pages)
   */
  async downloadCurrentNotebook() {
    this.logger.log('Downloading entire notebook...');

    // First, expand all section groups
    await this.expandSectionGroups();

    const sectionElements = await this.driver.$$(SELECTORS.SECTIONS_IN_NOTEBOOK);
    if (sectionElements.length === 0) {
      this.logger.warn('No sections found in current notebook.');
      return;
    }

    this.logger.log(`Found ${sectionElements.length} sections in notebook.`);

    for (let i = 0; i < sectionElements.length; i++) {
      try {
        this.logger.log(`Processing section ${i + 1}/${sectionElements.length}...`);

        // Get the section name before clicking
        const sectionElement = await this.driver.$$(SELECTORS.SECTIONS_IN_NOTEBOOK);
        if (sectionElement[i]) {
          const sectionName = await sectionElement[i].evaluate(el => el.textContent.trim());
          const safeSectionName = sectionName.replace(/[^a-z0-9]/giu, '_').toLowerCase();
          
          // Create section folder
          this.currentSectionFolder = safeSectionName;
          await fs.mkdir(this.currentSectionFolder, { recursive: true });
          this.logger.log(`Created folder for section: ${this.currentSectionFolder}`);

          await sectionElement[i].click();
          await this.waitForPageLoad();

          // Download all pages in this section
          await this.downloadCurrentSection();
        }
      } catch (error) {
        this.logger.error(`Error processing section ${i + 1}:`, error.message);
      }
    }

    // Reset section folder after notebook download
    this.currentSectionFolder = null;
  }

  /**
   * Expand all section groups in the navigation pane
   */
  async expandSectionGroups() {
    try {
      const groupElements = await this.driver.$$(SELECTORS.SECTION_GROUPS);
      this.logger.log(`Expanding ${groupElements.length} section groups...`);

      for (const groupElement of groupElements) {
        try {
          await groupElement.click();
          await this.driver.waitForTimeout(WAIT_TIME_MS / 2);
        } catch (error) {
          // Some elements might not be clickable, continue
          this.logger.debug('Could not click section group:', error.message);
        }
      }

      await this.waitForPageLoad();
    } catch (error) {
      this.logger.warn('Error expanding section groups:', error.message);
    }
  }

  /**
   * Wait for page to load
   */
  async waitForPageLoad() {
    await this.driver.waitForTimeout(WAIT_TIME_MS);
  }

  /**
   * Download the content frame of the OneNote page to a file
   */
  async downloadCurrentPage() {
    const contentFrame = this.driver.frames().find(frame => frame.name() === SELECTORS.CONTENT_FRAME);
    if (!contentFrame) {
      throw new Error('Did not find content frame.');
    }

    const content = await contentFrame.$(SELECTORS.PAGE_CONTENT);
    if (!content) {
      throw new Error('Did not find page content.');
    }

    const title = await content.$eval(SELECTORS.PAGE_TITLE, e => e.innerText).catch(() => 'untitled');
    const saveTitle = title.replace(/[^a-z0-9]/giu, '_').toLowerCase();
    const saveEnding = crypto.randomBytes(RANDOM_BYTES_LENGTH).toString('hex');
    let filename = `${saveTitle}_${saveEnding}.html`;

    // If we're in a section folder (notebook download mode), save to that folder
    if (this.currentSectionFolder) {
      filename = path.join(this.currentSectionFolder, filename);
    }

    const htmlContent = await content.evaluate(node => node.innerHTML);
    const cleanedHtml = this.cleanupHtml(htmlContent);

    await fs.writeFile(filename, cleanedHtml, {encoding: 'utf8'});
    this.logger.info(`Wrote file "${filename}"`);
  }

  /**
   * Set up the browser
   */
  async initializeBrowser() {
    this.browser = await puppeteer.launch({
      headless: false,
      userDataDir: './user_data'
    });
    await this.openNewPage();
  }

  /**
   * Open a new page/tab
   */
  async openNewPage() {
    try {
      this.driver = await this.browser.newPage();
      await this.driver.setViewport({
        height: 1080,
        width: 1920
      });
    } catch (error) {
      this.logger.error(error);
      throw error;
    }
  }

  /**
   * Cleanup browser resources
   */
  async cleanup() {
    if (this.driver) {
      await this.driver.close();
    }
    if (this.browser) {
      await this.browser.close();
    }
  }

  /**
   * Cleanup the HTML
   * @param {string} htmlString the HTML to clean
   * @returns {string} the cleaned HTML
   */
  cleanupHtml(htmlString) {
    const $ = cheerio.load(htmlString);

    $('[unselectable="on"]').remove();
    $('span.DragHandle').remove();
    $('.HiddenParagraph').remove();

    return $.html();
  }
}

// Handle process termination gracefully
process.on('SIGINT', async () => {
  console.log('\nReceived SIGINT. Gracefully shutting down...');
  process.exit(EXIT_SUCCESS);
});

process.on('unhandledRejection', (reason, promise) => {
  console.error('Unhandled Rejection at:', promise, 'reason:', reason);
  process.exit(1);
});

/**
 * Main execution function
 */
async function main() {
  const exporter = new InteractiveExporter();
  try {
    const exitCode = await exporter.run();
    process.exit(exitCode);
  } catch (error) {
    console.error('Fatal error:', error.message);
    await exporter.cleanup();
    process.exit(1);
  }
}

main();
