# TODO

Ideas and future plans for r2mcp

* Extensions/Plugins
  * Let the user load an .r2.js script or yaml file to define new tools or prompts
  * Support loading custom plugins written in C or other languages
* Resources and Templates
  * Strings, symbols, relocs, imports, libraries, ..
  * Reversing context with user comments and project memory
* Prompts in filesystem instead of hardcoded inside the executable
  * Easier to maintain, user-customizable prompts for different analysis scenarios
  * Support templates (yaml definition for parameters?) to make prompts more concise
  * Automated report generation
* Advanced Analysis Tools
  * Find path between two points in the program
  * Progressive analysis and avoid analyzing twice (Optimized analysis for large binaries)
  * Support loading and unloading multiple files
* Projects Support
  * Function signature matching and library identification
  * Caching of analysis results
  * Export analysis results to various formats (JSON, XML, GraphML)
  * Import external analysis data
* Debugging Integration (Requires providing permissions to do it)
  * Support for emulation and native debugging
  * Spawn or Attach to running processes
  * Step-through debugging with breakpoints
  * Memory inspection and modification
  * Register state analysis
* User Interface and Testing Q&A
  * Documentation and tutorials
  * User-contributed scripts and templates
  * Comprehensive test suite for all tools
