# OneNoteExporter
Export some OneNote pages as a combined HTML file.

At the moment, it works for me, but may need additional adjustments for your use.

## Overview

Motivation: export certain pages automated.

Unfortunately, I did not find an easy way around a web-interface for the Office 365 login.

## Usage
 
 - create a msal.config.js file in the config folder, fill it appropriately as listed in the msal documentation
 - Use `yarn compile` to run browserify (make sure to have it installed).
 - Use the files src/one-note-diary-export.{bundle.js, html} on your server. Have fun.
