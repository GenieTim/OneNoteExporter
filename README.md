# OneNoteExporter
Export some OneNote pages as a combined HTML file.

At the moment, it works for me, but may need additional adjustments for your use.
An introduction how I used this repo can be found in my [Blog](https://www.genieblog.ch/blog/en/2020/onennote-to-latex).

- [OneNoteExporter](#onenoteexporter)
  - [Overview](#overview)
  - [Usage](#usage)
    - [Using API](#using-api)
    - [Using Browser](#using-browser)

## Overview

Motivation: export certain pages automated.

Unfortunately, I did not find an easy way around a web-interface for the Office 365 login except for the direct interaction with OneNote online. Read further for the two approaches and their benefits.

## Usage

Make sure to have [NodeJS](https://nodejs.org/en/) and [yarn](https://yarnpkg.com/) installed.
After downloading the repository, run `yarn` in this directory to install all necessary components.

### Using API 
This approach uses the official OneNote API (resp. Microsoft Graph). 
A webpage helps to choose which pages to download if you don't know their IDs.

 - create a msal.config.js file in the config folder, fill it appropriately as listed in the msal documentation
 - Use `yarn compile` to run browserify (make sure to have it installed).
 - Use the files src/one-note-diary-export.{bundle.js, html} on your server. Have fun.

### Using Browser
This approach uses Puppeteer so you can just navigate to the page in OneNote online to download the relative pages.
Advantage includes an easier application (no need to register this app in your Azure AD) 
and more content (math equations are not supported by the API). 
Disadvantages include more complicated HTML and more manual work, as you have to export each page separately.

 - Run `node ./bin/interactive-exporter.js` 
 - Follow the instructions in the CMD/act accordingly in the browser.
