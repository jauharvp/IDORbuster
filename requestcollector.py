from burp import IBurpExtender, ITab, IContextMenuFactory, IContextMenuInvocation, IHttpRequestResponse
from java.awt import BorderLayout, FlowLayout, GridLayout, Dimension
from java.awt.event import ActionListener, ItemListener
from java.io import File, FileWriter
from javax.swing import (JPanel, JLabel, JButton, JComboBox, JTextField, JScrollPane, 
                        JTable, JMenuItem, JFileChooser, DefaultCellEditor, BorderFactory,
                        JCheckBox, BoxLayout, Box, JSplitPane)
from javax.swing.table import DefaultTableModel
from javax.swing.event import ListSelectionListener
from java.net import URL
from java.util import ArrayList

class BurpExtender(IBurpExtender, ITab, IContextMenuFactory):
    # Implement IBurpExtender
    def registerExtenderCallbacks(self, callbacks):
        # Keep a reference to our callbacks object
        self._callbacks = callbacks
        
        # Set our extension name
        callbacks.setExtensionName("Request Filter")
        
        # Initialize the request list and filtered list
        self._requestList = ArrayList()
        self._filteredList = ArrayList()
        
        # Create UI
        self._initUI()
        
        # Register context menu
        callbacks.registerContextMenuFactory(self)
        
        # Register ourselves as a custom tab
        callbacks.addSuiteTab(self)
        
        # Get helpers
        self._helpers = callbacks.getHelpers()
        
        print("Request Filter plugin loaded!")
    
    # Initialize UI components
    def _initUI(self):
        # Create main panel with resizability
        self._mainPanel = JPanel(BorderLayout())
        self._mainPanel.setPreferredSize(Dimension(1000, 700))  # Set initial preferred size
        
        # Create filter panel at the top with multiple rows
        filterPanel = JPanel()
        filterPanel.setLayout(BoxLayout(filterPanel, BoxLayout.Y_AXIS))
        
        # HTTP Method filter panel (checkboxes)
        methodPanel = JPanel(FlowLayout(FlowLayout.LEFT))
        methodPanel.add(JLabel("HTTP Methods:"))
        
        # Create method checkboxes
        self._methodFilters = {}
        methodNames = ["GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH"]
        
        for method in methodNames:
            checkbox = JCheckBox(method, True)  # All selected by default
            self._methodFilters[method] = checkbox
            methodPanel.add(checkbox)
        
        filterPanel.add(methodPanel)
        
        # File type filter panel (checkboxes)
        fileTypePanel = JPanel(FlowLayout(FlowLayout.LEFT))
        fileTypePanel.add(JLabel("File Types:"))
        
        # Create file type checkboxes
        self._fileTypeFilters = {}
        fileTypes = ["js", "gif", "jpg", "png", "css"]
        
        # Add checkbox to include/exclude these file types
        self._includeFileTypes = JCheckBox("Include", False)  # Default is to exclude
        fileTypePanel.add(self._includeFileTypes)
        
        for fileType in fileTypes:
            checkbox = JCheckBox(fileType, True)  # All selected by default
            self._fileTypeFilters[fileType] = checkbox
            fileTypePanel.add(checkbox)
        
        filterPanel.add(fileTypePanel)
        
        # URI filter panel with multiple filters
        uriPanel = JPanel(FlowLayout(FlowLayout.LEFT))
        
        # URI Filter label
        uriPanel.add(JLabel("URI Filters:"))
        
        # URI filter list panel
        self._uriFilters = []
        
        # Initial URI filter
        firstUriFilter = JTextField(30)
        self._uriFilters.append(firstUriFilter)
        uriPanel.add(firstUriFilter)
        
        # Add URI filter button
        addUriButton = JButton("+")
        addUriButton.setToolTipText("Add another URI filter")
        addUriButton.addActionListener(AddUriFilterListener(self))
        uriPanel.add(addUriButton)
        
        # Apply filter button
        self._filterButton = JButton("Apply Filter")
        self._filterButton.addActionListener(FilterListener(self))
        uriPanel.add(self._filterButton)
        
        filterPanel.add(uriPanel)
        
        self._mainPanel.add(filterPanel, BorderLayout.NORTH)
        
        # Create table to hold request data
        self._tableModel = DefaultTableModel()
        self._tableModel.addColumn("ID")
        self._tableModel.addColumn("Method")
        self._tableModel.addColumn("URL")
        self._tableModel.addColumn("Status")
        self._tableModel.addColumn("Length")
        
        self._table = JTable(self._tableModel)
        self._table.getSelectionModel().addListSelectionListener(TableSelectionListener(self))
        
        # Set column widths
        self._table.getColumnModel().getColumn(0).setPreferredWidth(50)
        self._table.getColumnModel().getColumn(1).setPreferredWidth(80)
        self._table.getColumnModel().getColumn(2).setPreferredWidth(350)
        self._table.getColumnModel().getColumn(3).setPreferredWidth(80)
        self._table.getColumnModel().getColumn(4).setPreferredWidth(80)
        
        # Add table to a scroll pane
        tableScrollPane = JScrollPane(self._table)
        
        # Create details panel for request/response
        detailsPanel = JPanel(BorderLayout())
        
        # Create a split pane for the request and response viewers
        viewerSplitPane = JSplitPane(JSplitPane.VERTICAL_SPLIT)
        viewerSplitPane.setResizeWeight(0.5)  # Equal resizing for both components
        
        # Request viewer
        requestPanel = JPanel(BorderLayout())
        requestPanel.setBorder(BorderFactory.createTitledBorder("Request"))
        self._requestViewer = self._callbacks.createMessageEditor(None, False)
        requestPanel.add(self._requestViewer.getComponent(), BorderLayout.CENTER)
        viewerSplitPane.setTopComponent(requestPanel)
        
        # Response viewer
        responsePanel = JPanel(BorderLayout())
        responsePanel.setBorder(BorderFactory.createTitledBorder("Response"))
        self._responseViewer = self._callbacks.createMessageEditor(None, False)
        responsePanel.add(self._responseViewer.getComponent(), BorderLayout.CENTER)
        viewerSplitPane.setBottomComponent(responsePanel)
        
        # Add to details panel
        detailsPanel.add(viewerSplitPane, BorderLayout.CENTER)
        
        # Create navigation buttons
        navPanel = JPanel(FlowLayout(FlowLayout.CENTER))
        
        # Previous button
        prevButton = JButton("< Previous Request")
        prevButton.addActionListener(NavigationListener(self, -1))
        navPanel.add(prevButton)
        
        # Next button
        nextButton = JButton("Next Request >")
        nextButton.addActionListener(NavigationListener(self, 1))
        navPanel.add(nextButton)
        
        detailsPanel.add(navPanel, BorderLayout.SOUTH)
        
        # Create a split pane for table and details
        mainSplitPane = JSplitPane(JSplitPane.VERTICAL_SPLIT, tableScrollPane, detailsPanel)
        mainSplitPane.setResizeWeight(0.5)  # Equal resizing for both components
        mainSplitPane.setDividerLocation(300)  # Initial divider position
        
        # Add the split pane to the center of the main panel
        self._mainPanel.add(mainSplitPane, BorderLayout.CENTER)
        
        # Create action panel
        actionPanel = JPanel()
        actionPanel.setLayout(BoxLayout(actionPanel, BoxLayout.X_AXIS))
        
        actionPanel.add(Box.createHorizontalGlue())
        
        # Save button
        self._saveButton = JButton("Save Selected as HTTP File")
        self._saveButton.addActionListener(SaveListener(self))
        actionPanel.add(self._saveButton)
        
        actionPanel.add(Box.createHorizontalStrut(10))
        
        # Save All button
        self._saveAllButton = JButton("Save All Requests to Folder")
        self._saveAllButton.addActionListener(SaveAllListener(self))
        actionPanel.add(self._saveAllButton)
        
        actionPanel.add(Box.createHorizontalStrut(10))
        
        # Clear button
        self._clearButton = JButton("Clear All")
        self._clearButton.addActionListener(ClearListener(self))
        actionPanel.add(self._clearButton)
        
        actionPanel.add(Box.createHorizontalGlue())
        
        self._mainPanel.add(actionPanel, BorderLayout.SOUTH)
    
    # Check if URL has one of the specified file extensions
    def _hasFileExtension(self, url, extensions):
        for ext in extensions:
            if url.lower().endswith("." + ext.lower()):
                return True
        return False
    
    # Filter requests based on current filter settings
    def _applyFilters(self):
        self._filteredList.clear()
        
        for reqRes in self._requestList:
            try:
                # Parse the request
                request = reqRes.getRequest()
                requestInfo = self._helpers.analyzeRequest(reqRes)
                
                # Get HTTP method
                method = requestInfo.getMethod()
                
                # Get URL
                url = requestInfo.getUrl().toString()
                
                # Apply method filter - check if current method is selected
                if method in self._methodFilters:
                    if not self._methodFilters[method].isSelected():
                        continue
                else:
                    # If method not in our predefined list, skip if not a selected "OTHER" checkbox
                    # (could add an "OTHER" checkbox in the future)
                    continue
                
                # Apply file type filters
                selectedFileTypes = [ext for ext, checkbox in self._fileTypeFilters.items() 
                                    if checkbox.isSelected()]
                
                isFileTypeMatch = self._hasFileExtension(url, selectedFileTypes)
                
                # If include is checked, we want to keep file type matches
                # If include is not checked, we want to exclude file type matches
                if self._includeFileTypes.isSelected():
                    # Include mode - skip if not a file type match
                    if selectedFileTypes and not isFileTypeMatch:
                        continue
                else:
                    # Exclude mode - skip if it is a file type match
                    if isFileTypeMatch:
                        continue
                
                # Apply URI filters if any are not empty
                matchesUriFilter = False
                
                # If all URI filters are empty, consider it a match
                if all(filter.getText().strip() == "" for filter in self._uriFilters):
                    matchesUriFilter = True
                else:
                    # Check each non-empty filter - ANY match passes (OR logic)
                    for uriFilter in self._uriFilters:
                        filterText = uriFilter.getText().strip()
                        if filterText and filterText in url:
                            matchesUriFilter = True
                            break
                
                if not matchesUriFilter:
                    continue
                
                # If we got here, request passed all filters
                self._filteredList.add(reqRes)
            except Exception as e:
                print("Error filtering request: {}".format(e))
        
        # Update the table
        self._updateTable()
    
    # Update the table with filtered requests
    def _updateTable(self):
        # Clear the table
        while self._tableModel.getRowCount() > 0:
            self._tableModel.removeRow(0)
        
        # Add filtered requests to table
        for i, reqRes in enumerate(self._filteredList):
            try:
                # Parse the request
                request = reqRes.getRequest()
                requestInfo = self._helpers.analyzeRequest(reqRes)
                
                # Get method
                method = requestInfo.getMethod()
                
                # Get URL
                url = requestInfo.getUrl().toString()
                
                # Get response info if available
                responseStatus = ""
                responseLength = ""
                
                response = reqRes.getResponse()
                if response:
                    responseInfo = self._helpers.analyzeResponse(response)
                    responseStatus = str(responseInfo.getStatusCode())
                    responseLength = str(len(response))
                
                # Add row to table
                self._tableModel.addRow([str(i), method, url, responseStatus, responseLength])
            except Exception as e:
                print("Error updating table: {}".format(e))
    
    # Extract filename from URL
    def _getFilenameFromUrl(self, urlString):
        try:
            # Try to parse as URL
            url = URL(urlString)
            
            # Get path
            path = url.getPath()
            
            # Split path and get last part
            pathParts = path.split("/")
            
            # Find last non-empty part
            filename = "request"
            for part in reversed(pathParts):
                if part:
                    filename = part
                    break
            
            # Remove query parameters if present
            if "?" in filename:
                filename = filename.split("?")[0]
            
            # Add .http extension if needed
            if not filename.endswith(".http"):
                filename += ".http"
            
            return filename
        except:
            # If URL parsing fails, return a default name
            return "request.http"
    
    # Add a request to the list
    def addRequest(self, reqRes):
        self._requestList.add(reqRes)
        self._applyFilters()
    
    # Save the selected request as a file
    def saveSelectedRequest(self):
        # Get selected row
        row = self._table.getSelectedRow()
        if row == -1:
            return
        
        # Get the request response object
        reqRes = self._filteredList.get(row)
        
        # Get URL
        url = self._tableModel.getValueAt(row, 2)
        
        # Generate filename
        filename = self._getFilenameFromUrl(url)
        
        # Create file chooser
        fileChooser = JFileChooser()
        fileChooser.setSelectedFile(File(filename))
        
        # Show save dialog
        result = fileChooser.showSaveDialog(self._mainPanel)
        
        if result == JFileChooser.APPROVE_OPTION:
            file = fileChooser.getSelectedFile()
            
            try:
                # Write raw request to file
                fw = FileWriter(file)
                fw.write(self._helpers.bytesToString(reqRes.getRequest()))
                fw.close()
                print("Request saved to {}".format(file.getAbsolutePath()))
            except Exception as e:
                print("Error saving request: {}".format(e))
    
    # Save all filtered requests to a directory
    def saveAllRequests(self):
        # Check if there are any filtered requests
        if self._filteredList.isEmpty():
            return
        
        # Create directory chooser
        fileChooser = JFileChooser()
        fileChooser.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY)
        fileChooser.setDialogTitle("Select Directory to Save All Requests")
        
        # Show dialog
        result = fileChooser.showSaveDialog(self._mainPanel)
        
        if result == JFileChooser.APPROVE_OPTION:
            directory = fileChooser.getSelectedFile()
            
            # Create directory if it doesn't exist
            if not directory.exists():
                directory.mkdirs()
            
            # Save each request
            savedCount = 0
            errorCount = 0
            
            for i in range(self._filteredList.size()):
                try:
                    # Get request response
                    reqRes = self._filteredList.get(i)
                    
                    # Get URL
                    url = self._tableModel.getValueAt(i, 2)
                    
                    # Generate filename based on URL
                    filename = self._getFilenameFromUrl(url)
                    
                    # Handle duplicate filenames by adding a number
                    baseFilename = filename
                    counter = 1
                    outputFile = File(directory, filename)
                    
                    while outputFile.exists():
                        # If file already exists, add a counter before the extension
                        nameParts = baseFilename.rsplit('.', 1)
                        if len(nameParts) > 1:
                            filename = "{}-{}{}".format(nameParts[0], counter, nameParts[1])
                        else:
                            filename = "{}-{}".format(baseFilename, counter)
                        
                        outputFile = File(directory, filename)
                        counter += 1
                    
                    # Write request to file
                    fw = FileWriter(outputFile)
                    fw.write(self._helpers.bytesToString(reqRes.getRequest()))
                    fw.close()
                    
                    savedCount += 1
                except Exception as e:
                    print("Error saving request {}: {}".format(i, e))
                    errorCount += 1
            
            print("Saved {} requests to {}. Errors: {}".format(
                savedCount, directory.getAbsolutePath(), errorCount))
    
    # Add a new URI filter field
    def addUriFilter(self):
        if len(self._uriFilters) < 5:  # Limit to 5 filters for UI reasons
            newFilter = JTextField(30)
            self._uriFilters.append(newFilter)
            
            # Get the URI panel (third component in the filter panel)
            filterPanel = self._mainPanel.getComponent(0)
            uriPanel = filterPanel.getComponent(2)
            
            # Insert before the + button and Apply button
            uriPanel.add(newFilter, uriPanel.getComponentCount() - 2)
            
            # Refresh UI
            uriPanel.revalidate()
            uriPanel.repaint()
    
    # Navigate to next/previous request
    def navigateRequest(self, direction):
        # Get current selection
        row = self._table.getSelectedRow()
        if row == -1:
            # If nothing selected, select first row if navigating forward
            if direction > 0 and self._tableModel.getRowCount() > 0:
                self._table.setRowSelectionInterval(0, 0)
            return
        
        # Calculate new row
        newRow = row + direction
        
        # Check bounds
        if 0 <= newRow < self._tableModel.getRowCount():
            # Select new row
            self._table.setRowSelectionInterval(newRow, newRow)
            
            # Ensure new row is visible
            self._table.scrollRectToVisible(self._table.getCellRect(newRow, 0, True))
    
    # Implement ITab
    def getTabCaption(self):
        return "Request Filter"
    
    def getUiComponent(self):
        return self._mainPanel
    
    # Implement IContextMenuFactory
    def createMenuItems(self, invocation):
        # Create a list to hold menu items
        menuItems = ArrayList()
        
        # Only show menu items for HTTP history
        if invocation.getInvocationContext() == IContextMenuInvocation.CONTEXT_PROXY_HISTORY:
            # Get selected messages
            selectedMessages = invocation.getSelectedMessages()
            
            if selectedMessages and len(selectedMessages) > 0:
                # Create menu item
                menuItem = JMenuItem("Send to Request Filter")
                menuItem.addActionListener(SendToFilterListener(self, selectedMessages))
                menuItems.add(menuItem)
        
        return menuItems


# Listener for filter button
class FilterListener(ActionListener):
    def __init__(self, extender):
        self._extender = extender
    
    def actionPerformed(self, e):
        self._extender._applyFilters()

# Listener for table selection
class TableSelectionListener(ListSelectionListener):
    def __init__(self, extender):
        self._extender = extender
    
    def valueChanged(self, e):
        if not e.getValueIsAdjusting():
            row = self._extender._table.getSelectedRow()
            if row != -1:
                # Get the request response object
                reqRes = self._extender._filteredList.get(row)
                
                # Update request/response viewers
                self._extender._requestViewer.setMessage(reqRes.getRequest(), True)
                
                response = reqRes.getResponse()
                if response:
                    self._extender._responseViewer.setMessage(response, False)
                else:
                    self._extender._responseViewer.setMessage(None, False)

# Listener for save button
class SaveListener(ActionListener):
    def __init__(self, extender):
        self._extender = extender
    
    def actionPerformed(self, e):
        self._extender.saveSelectedRequest()

# Listener for save all button
class SaveAllListener(ActionListener):
    def __init__(self, extender):
        self._extender = extender
    
    def actionPerformed(self, e):
        self._extender.saveAllRequests()

# Listener for clear button
class ClearListener(ActionListener):
    def __init__(self, extender):
        self._extender = extender
    
    def actionPerformed(self, e):
        self._extender._requestList.clear()
        self._extender._filteredList.clear()
        self._extender._updateTable()
        self._extender._requestViewer.setMessage(None, True)
        self._extender._responseViewer.setMessage(None, False)

# Listener for "Send to Filter" context menu
class SendToFilterListener(ActionListener):
    def __init__(self, extender, messages):
        self._extender = extender
        self._messages = messages
    
    def actionPerformed(self, e):
        for message in self._messages:
            self._extender.addRequest(message)

# Listener for the Add URI Filter button
class AddUriFilterListener(ActionListener):
    def __init__(self, extender):
        self._extender = extender
    
    def actionPerformed(self, e):
        self._extender.addUriFilter()

# Listener for navigation buttons
class NavigationListener(ActionListener):
    def __init__(self, extender, direction):
        self._extender = extender
        self._direction = direction  # -1 for previous, 1 for next
    
    def actionPerformed(self, e):
        self._extender.navigateRequest(self._direction)
