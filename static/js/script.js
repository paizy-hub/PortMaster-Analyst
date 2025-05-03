// Global variables
let currentScanId = null;
let updateIntervalId = null;
let historyLoaded = false;

// Initialize the page
$(document).ready(function() {
    // Handle form submission
    $('#scan-form').on('submit', function(e) {
        e.preventDefault();
        startScan();
    });
    
    // Load scan history
    loadScanHistory();
});

// Start a new scan
function startScan() {
    // Ambil nilai input dari form
    const target = $('#target').val().trim();
    const algorithm = $('input[name="algorithm"]:checked').val();
    const commonPortsFirst = $('#common_ports_first').is(':checked');
    const maxThreads = parseInt($('#max_threads').val()) || 10;
    const portRangeStart = parseInt($('#port_range_start').val()) || 1;
    const portRangeEnd = parseInt($('#port_range_end').val()) || 1024;

    // Validasi input target
    if (!target) {
        alert('Please enter a target IP address');
        return;
    }

    // Validasi port range
    if (portRangeStart > portRangeEnd) {
        alert('Port range start must be less than or equal to port range end');
        return;
    }

    if (portRangeStart < 1 || portRangeEnd > 65535) {
        alert('Port range must be between 1 and 65535');
        return;
    }

    // Siapkan data untuk dikirim ke API
    const scanData = {
        target: target,
        algorithm: algorithm,
        common_ports_first: commonPortsFirst,
        max_threads: maxThreads,
        port_range_start: portRangeStart,
        port_range_end: portRangeEnd
    };

    // Reset UI hasil sebelumnya
    $('#open-ports-list').empty();
    $('#port-count span').text('0');
    $('#scan-progress-bar').css('width', '0%');
    $('#progress-percent').text('0%');
    $('#current-scan').show();
    $('#scan-results').hide();

    // Kirim request ke server
    $.ajax({
        url: '/api/scan',
        type: 'POST',
        contentType: 'application/json',
        data: JSON.stringify(scanData),
        success: function(response) {
            currentScanId = response.scan_id;
            updateScanStatus();

            // Hentikan polling sebelumnya jika ada
            if (updateIntervalId) {
                clearInterval(updateIntervalId);
            }
            updateIntervalId = setInterval(updateScanStatus, 1000);
        },
        error: function(xhr, status, error) {
            alert('Error starting scan: ' + error);
            $('#current-scan').hide();
        }
    });
}

// Update open ports display during scan
function updateOpenPorts(openPorts) {
    $('#port-count span').text(openPorts.length);
    
    // Clear previous ports
    $('#open-ports-list').empty();
    
    // Add ports as badges
    openPorts.forEach(function(portData) {
        const portBadge = $('<span class="badge bg-success port-badge"></span>')
            .text(portData.port + ' (' + portData.service + ')');
        $('#open-ports-list').append(portBadge);
    });
}

// Display final results when scan completes
function displayFinalResults(data) {
    // Populate results data
    $('#results-target').text(data.target);
    $('#results-algorithm').text(data.algorithm);
    $('#results-start-time').text(data.start_time);
    $('#results-end-time').text(data.end_time || 'N/A');
    $('#results-duration').text(data.elapsed_time || 'N/A');
    $('#results-ports-scanned').text(data.total_ports);
    
    // Populate ports table
    $('#results-ports-table').empty();
    if (data.open_ports.length > 0) {
        // Sort ports by risk level (Critical -> High -> Medium -> Low -> Unknown)
        const riskOrder = {
            'Critical': 1,
            'High': 2, 
            'Medium': 3, 
            'Low': 4, 
            'Unknown': 5
        };
        
        data.open_ports.sort((a, b) => {
            return (riskOrder[a.risk_level] || 999) - (riskOrder[b.risk_level] || 999);
        });
        
        data.open_ports.forEach(function(portData, index) {
            const row = $('<tr></tr>');
            row.append($('<td></td>').text(portData.port));
            row.append($('<td></td>').text(portData.service));
            
            // Risk level with color-coded badge
            const riskLevel = portData.risk_level || 'Unknown';
            const riskBadge = $('<span class="risk-badge"></span>')
                .addClass('risk-' + riskLevel.toLowerCase())
                .text(riskLevel);
            row.append($('<td></td>').append(riskBadge));
            
            // Details button
            const detailsButton = $('<span class="port-details-button"></span>')
                .html('<i class="fas fa-info-circle"></i> Info')
                .attr('data-port-index', index);

            row.append($('<td></td>').append(detailsButton));
            
            $('#results-ports-table').append(row);
            
            // Add hidden details panel row
            const detailsRow = $('<tr class="port-details-row" style="display: none;"></tr>');
            const detailsCell = $('<td colspan="4"></td>');
            const detailsPanel = $('<div class="port-details-panel"></div>')
                .addClass('risk-' + riskLevel.toLowerCase() + '-panel');
            
            // Risk description
            if (portData.risk_description) {
                detailsPanel.append(
                    $('<div class="port-details-header"></div>').text('Risk Description:'),
                    $('<div class="port-details-content"></div>').text(portData.risk_description)
                );
            }
            
            // Recommendations
            if (portData.recommendations) {
                detailsPanel.append(
                    $('<div class="port-details-header"></div>').text('Recommendations:'),
                    $('<div class="port-details-content"></div>').text(portData.recommendations)
                );
            }
            
            detailsCell.append(detailsPanel);
            detailsRow.append(detailsCell);
            $('#results-ports-table').append(detailsRow);
        });
        
        // Add click handlers for details buttons
        $('.port-details-button').on('click', function() {
            const index = $(this).data('port-index');
            $(this).closest('tr').next('.port-details-row').toggle();
        });
    } else {
        const row = $('<tr></tr>');
        row.append($('<td colspan="4" class="text-center"></td>').text('No open ports found'));
        $('#results-ports-table').append(row);
    }
    
    // Show results section
    $('#scan-results').show();
}

// Load scan history
function loadScanHistory() {
    $.ajax({
        url: '/api/scans',
        type: 'GET',
        success: function(scans) {
            // Clear history list
            $('#history-list').empty();
            
            if (scans.length === 0) {
                $('#history-list').append('<div class="col-12 text-center"><p>No scan history yet</p></div>');
                return;
            }
            
            // Sort scans by start time (newest first)
            scans.sort(function(a, b) {
                return new Date(b.start_time) - new Date(a.start_time);
            });
            
            // Add each scan to history
            scans.forEach(function(scan) {
                const historyItem = createHistoryItem(scan);
                $('#history-list').append(historyItem);
            });
            
            // Add click handlers
            $('.history-item').on('click', function() {
                const scanId = $(this).data('scan-id');
                loadScanDetails(scanId);
            });
            
            historyLoaded = true;
        },
        error: function() {
            console.log('Error loading scan history');
        }
    });
}

// Create a history item element
function createHistoryItem(scan) {
    const statusClass = scan.status === 'completed' ? 'completed' : 
                        scan.status === 'running' ? 'running' : 'failed';
    
    const portCount = scan.open_ports ? scan.open_ports.length : 0;
    
    const historyCol = $('<div class="col-md-6 col-lg-4"></div>');
    const historyItem = $('<div class="history-item"></div>')
        .addClass(statusClass)
        .data('scan-id', scan.scan_id);
    
    historyItem.append($('<h5></h5>').text('Target: ' + scan.target));
    
    const detailsRow = $('<div class="row"></div>');
    
    const col1 = $('<div class="col-6"></div>');
    col1.append($('<p class="mb-1"></p>').text('Algorithm: ' + scan.algorithm));
    col1.append($('<p class="mb-1"></p>').text('Open Ports: ' + portCount));
    
    const col2 = $('<div class="col-6"></div>');
    col2.append($('<p class="mb-1"></p>').text('Date: ' + scan.start_time.split(' ')[0]));
    col2.append($('<p class="mb-1"></p>').text('Status: ' + scan.status));
    
    detailsRow.append(col1).append(col2);
    historyItem.append(detailsRow);
    
    historyCol.append(historyItem);
    return historyCol;
}

// Load details of a specific scan
function loadScanDetails(scanId) {
    $.ajax({
        url: '/api/scan/' + scanId,
        type: 'GET',
        success: function(data) {
            currentScanId = scanId;
            
            // If scan is still running, start updates
            if (data.status === 'running') {
                if (updateIntervalId) {
                    clearInterval(updateIntervalId);
                }
                updateIntervalId = setInterval(updateScanStatus, 1000);
                
                // Show current scan view
                $('#current-scan').show();
                $('#scan-results').hide();
                
                // Update status badge
                $('#scan-status-badge').removeClass('bg-success').addClass('bg-warning').text('Scanning...');
            } else {
                // Show completed results
                $('#current-scan').hide();
                displayFinalResults(data);
            }
            
            // Scroll to results
            $('html, body').animate({
                scrollTop: $('#scan-results').offset().top - 100
            }, 500);
        },
        error: function() {
            alert('Error loading scan details');
        }
    });
}

// Tambahkan fungsi untuk export PDF
function exportToPdf(scanId) {
    if (!scanId) return;
    
    // Buat URL untuk download PDF
    const pdfUrl = `/api/scan/${scanId}/export/pdf`;
    
    // Buat anchor element untuk download
    const link = document.createElement('a');
    link.href = pdfUrl;
    link.target = '_blank';
    
    // Trigger click untuk download
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
}

// Tambahkan event listener untuk export PDF button
$(document).ready(function() {
    // Existing handlers
    $('#scan-form').on('submit', function(e) {
        e.preventDefault();
        startScan();
    });
    
    // Load scan history
    loadScanHistory();
    
    // Add PDF export button handler
    $(document).on('click', '#export-pdf-btn', function() {
        exportToPdf(currentScanId);
    });
    
    // Validate port range inputs
    $('#port_range_start, #port_range_end').on('change', function() {
        const start = parseInt($('#port_range_start').val());
        const end = parseInt($('#port_range_end').val());
        
        if (start > end) {
            alert('Start port must be less than or equal to end port');
            $(this).val($(this).attr('id') === 'port_range_start' ? end : start);
        }
    });
});
