/**
 * Pwnagotchi Whitelist Plugin - Web Interface JavaScript
 * Provides dynamic functionality for the whitelist management interface
 */

class WhitelistManager {
    constructor() {
        this.networks = [];
        this.filteredNetworks = [];
        this.currentPage = 1;
        this.itemsPerPage = 25;
        this.searchTerm = '';
        this.filters = {
            type: 'all',
            status: 'all'
        };
        this.editingNetwork = null;
        
        // Rate limiting
        this.lastRequest = 0;
        this.requestDelay = 1000; // 1 second between requests
        
        this.init();
    }
    
    init() {
        this.bindEvents();
        this.loadNetworks();
        this.loadStats();
        
        // Auto-refresh every 30 seconds
        setInterval(() => {
            this.loadStats();
        }, 30000);
    }
    
    bindEvents() {
        // Navigation buttons
        $('#refresh-btn').on('click', () => this.refreshData());
        $('#add-network-btn').on('click', () => this.showAddModal());
        $('#import-btn').on('click', () => this.showImportModal());
        $('#export-btn').on('click', () => this.exportWhitelist());
        
        // Search and filters
        $('#search-input').on('input', (e) => this.handleSearch(e.target.value));
        $('#filter-type').on('change', (e) => this.handleFilter('type', e.target.value));
        $('#filter-status').on('change', (e) => this.handleFilter('status', e.target.value));
        $('#clear-filters').on('click', () => this.clearFilters());
        
        // Pagination
        $('#prev-page').on('click', () => this.changePage(this.currentPage - 1));
        $('#next-page').on('click', () => this.changePage(this.currentPage + 1));
        
        // Modal events
        $('#close-modal, #cancel-btn').on('click', () => this.hideModal());
        $('#close-import-modal, #cancel-import-btn').on('click', () => this.hideImportModal());
        $('#network-form').on('submit', (e) => this.handleSubmit(e));
        $('#import-confirm-btn').on('click', () => this.handleImport());
        
        // Form events
        $('#network-regex').on('change', (e) => this.toggleRegexPattern(e.target.checked));
        $('#import-file').on('change', (e) => this.handleFileUpload(e));
        
        // Table events (delegated)
        $('#whitelist-tbody').on('click', '.edit-btn', (e) => {
            const id = parseInt($(e.target).data('id'));
            this.editNetwork(id);
        });
        
        $('#whitelist-tbody').on('click', '.toggle-btn', (e) => {
            const id = parseInt($(e.target).data('id'));
            const enabled = $(e.target).data('enabled');
            this.toggleNetwork(id, !enabled);
        });
        
        $('#whitelist-tbody').on('click', '.delete-btn', (e) => {
            const id = parseInt($(e.target).data('id'));
            this.deleteNetwork(id);
        });
        
        // Close modals when clicking outside
        $(window).on('click', (e) => {
            if ($(e.target).hasClass('modal')) {
                this.hideModal();
                this.hideImportModal();
            }
        });
        
        // Keyboard shortcuts
        $(document).on('keydown', (e) => {
            if (e.key === 'Escape') {
                this.hideModal();
                this.hideImportModal();
            }
            if (e.ctrlKey && e.key === 'f') {
                e.preventDefault();
                $('#search-input').focus();
            }
            if (e.ctrlKey && e.key === 'n') {
                e.preventDefault();
                this.showAddModal();
            }
        });
    }
    
    async makeRequest(url, options = {}) {
        // Rate limiting
        const now = Date.now();
        if (now - this.lastRequest < this.requestDelay) {
            await new Promise(resolve => setTimeout(resolve, this.requestDelay - (now - this.lastRequest)));
        }
        this.lastRequest = Date.now();
        
        try {
            const response = await fetch(url, {
                headers: {
                    'Content-Type': 'application/json',
                    'X-Requested-With': 'XMLHttpRequest'
                },
                ...options
            });
            
            if (!response.ok) {
                throw new Error(`HTTP ${response.status}: ${response.statusText}`);
            }
            
            return await response.json();
        } catch (error) {
            console.error('Request failed:', error);
            this.showMessage(`Request failed: ${error.message}`, 'error');
            throw error;
        }
    }
    
    async loadNetworks() {
        try {
            this.showLoading(true);
            const data = await this.makeRequest('/api/whitelist');
            this.networks = data.networks || [];
            this.applyFilters();
            this.updateTable();
        } catch (error) {
            this.showMessage('Failed to load networks', 'error');
        } finally {
            this.showLoading(false);
        }
    }
    
    async loadStats() {
        try {
            const data = await this.makeRequest('/api/whitelist/stats');
            this.updateStats(data);
        } catch (error) {
            console.error('Failed to load stats:', error);
        }
    }
    
    updateStats(stats) {
        $('#stat-total').text(stats.total_networks || 0);
        $('#stat-active').text(stats.enabled_networks || 0);
        $('#stat-bssid').text(stats.bssid_entries || 0);
        $('#stat-ssid').text(stats.ssid_entries || 0);
        $('#stat-wildcard').text(stats.wildcard_entries || 0);
        
        const statusElement = $('#stat-status');
        if (stats.ready) {
            statusElement.text('Active').removeClass('error').addClass('success');
        } else {
            statusElement.text('Error').removeClass('success').addClass('error');
        }
    }
    
    applyFilters() {
        this.filteredNetworks = this.networks.filter(network => {
            // Search filter
            if (this.searchTerm) {
                const term = this.searchTerm.toLowerCase();
                const searchText = [
                    network.bssid || '',
                    network.ssid || '',
                    network.description || ''
                ].join(' ').toLowerCase();
                
                if (!searchText.includes(term)) {
                    return false;
                }
            }
            
            // Type filter
            if (this.filters.type !== 'all') {
                switch (this.filters.type) {
                    case 'bssid':
                        if (!network.bssid || network.ssid) return false;
                        break;
                    case 'ssid':
                        if (!network.ssid || network.bssid) return false;
                        break;
                    case 'both':
                        if (!network.bssid || !network.ssid) return false;
                        break;
                    case 'wildcard':
                        if (!network.use_wildcard) return false;
                        break;
                    case 'regex':
                        if (!network.use_regex) return false;
                        break;
                }
            }
            
            // Status filter
            if (this.filters.status !== 'all') {
                const enabled = network.enabled !== false;
                if (this.filters.status === 'enabled' && !enabled) return false;
                if (this.filters.status === 'disabled' && enabled) return false;
            }
            
            return true;
        });
        
        // Reset to first page when filters change
        this.currentPage = 1;
    }
    
    updateTable() {
        const tbody = $('#whitelist-tbody');
        tbody.empty();
        
        if (this.filteredNetworks.length === 0) {
            tbody.append(`
                <tr class="no-data">
                    <td colspan="8" class="text-center">
                        ${this.networks.length === 0 ? 'No networks in whitelist' : 'No networks match the current filters'}
                    </td>
                </tr>
            `);
            this.updatePagination(0, 0, 0);
            return;
        }
        
        // Calculate pagination
        const totalItems = this.filteredNetworks.length;
        const totalPages = Math.ceil(totalItems / this.itemsPerPage);
        const startIndex = (this.currentPage - 1) * this.itemsPerPage;
        const endIndex = Math.min(startIndex + this.itemsPerPage, totalItems);
        
        // Get page data
        const pageNetworks = this.filteredNetworks.slice(startIndex, endIndex);
        
        // Render rows
        const template = $('#network-row-template').html();
        pageNetworks.forEach(network => {
            const row = this.renderNetworkRow(network, template);
            tbody.append(row);
        });
        
        this.updatePagination(startIndex + 1, endIndex, totalItems);
    }
    
    renderNetworkRow(network, template) {
        const enabled = network.enabled !== false;
        const badges = [];
        
        if (network.use_wildcard) badges.push('<span class="badge badge-wildcard">*</span>');
        if (network.use_regex) badges.push('<span class="badge badge-regex">regex</span>');
        
        let type = 'Unknown';
        if (network.bssid && network.ssid) type = 'Both';
        else if (network.bssid) type = 'BSSID';
        else if (network.ssid) type = 'SSID';
        
        const addedDate = network.added_date ? 
            new Date(network.added_date).toLocaleDateString() : 'Unknown';
        
        return template
            .replace(/{id}/g, network.id || 'N/A')
            .replace(/{bssid}/g, network.bssid || '-')
            .replace(/{ssid}/g, this.escapeHtml(network.ssid || '-'))
            .replace(/{badges}/g, badges.join(' '))
            .replace(/{type}/g, type)
            .replace(/{status}/g, enabled ? 'Enabled' : 'Disabled')
            .replace(/{status-class}/g, enabled ? 'enabled' : 'disabled')
            .replace(/{added_date}/g, addedDate)
            .replace(/{description}/g, this.escapeHtml(network.description || ''))
            .replace(/{enabled}/g, enabled)
            .replace(/{toggle-icon}/g, enabled ? '🔒' : '🔓');
    }
    
    updatePagination(start, end, total) {
        $('#pagination-info').text(`Showing ${start} - ${end} of ${total} entries`);
        
        const totalPages = Math.ceil(total / this.itemsPerPage);
        $('#current-page-info').text(`Page ${this.currentPage} of ${Math.max(1, totalPages)}`);
        
        $('#prev-page').prop('disabled', this.currentPage <= 1);
        $('#next-page').prop('disabled', this.currentPage >= totalPages);
    }
    
    changePage(page) {
        const totalPages = Math.ceil(this.filteredNetworks.length / this.itemsPerPage);
        
        if (page < 1 || page > totalPages) return;
        
        this.currentPage = page;
        this.updateTable();
    }
    
    handleSearch(term) {
        this.searchTerm = term;
        this.applyFilters();
        this.updateTable();
    }
    
    handleFilter(type, value) {
        this.filters[type] = value;
        this.applyFilters();
        this.updateTable();
    }
    
    clearFilters() {
        this.searchTerm = '';
        this.filters = { type: 'all', status: 'all' };
        
        $('#search-input').val('');
        $('#filter-type').val('all');
        $('#filter-status').val('all');
        
        this.applyFilters();
        this.updateTable();
    }
    
    refreshData() {
        this.loadNetworks();
        this.loadStats();
        this.showMessage('Data refreshed', 'success');
    }
    
    showAddModal() {
        this.editingNetwork = null;
        $('#modal-title').text('Add Network to Whitelist');
        $('#network-form')[0].reset();
        $('#network-enabled').prop('checked', true);
        $('#regex-pattern-group').hide();
        $('#network-modal').show();
        $('#network-bssid').focus();
    }
    
    async editNetwork(id) {
        const network = this.networks.find(n => n.id === id);
        if (!network) return;
        
        this.editingNetwork = network;
        $('#modal-title').text('Edit Network');
        
        // Populate form
        $('#network-bssid').val(network.bssid || '');
        $('#network-ssid').val(network.ssid || '');
        $('#network-description').val(network.description || '');
        $('#network-enabled').prop('checked', network.enabled !== false);
        $('#network-wildcard').prop('checked', network.use_wildcard || false);
        $('#network-regex').prop('checked', network.use_regex || false);
        $('#network-regex-pattern').val(network.regex_pattern || '');
        $('#network-tags').val((network.tags || []).join(', '));
        
        this.toggleRegexPattern(network.use_regex || false);
        $('#network-modal').show();
    }
    
    async handleSubmit(e) {
        e.preventDefault();
        
        const formData = new FormData(e.target);
        const data = {
            bssid: formData.get('bssid') || null,
            ssid: formData.get('ssid') || null,
            description: formData.get('description') || '',
            enabled: formData.get('enabled') === 'on',
            use_wildcard: formData.get('use_wildcard') === 'on',
            use_regex: formData.get('use_regex') === 'on',
            regex_pattern: formData.get('regex_pattern') || null,
            tags: formData.get('tags') ? formData.get('tags').split(',').map(t => t.trim()).filter(t => t) : []
        };
        
        // Validation
        if (!data.bssid && !data.ssid) {
            this.showMessage('Either BSSID or SSID must be provided', 'error');
            return;
        }
        
        if (data.bssid && !this.validateBSSID(data.bssid)) {
            this.showMessage('Invalid BSSID format', 'error');
            return;
        }
        
        if (data.ssid && data.ssid.length > 32) {
            this.showMessage('SSID cannot be longer than 32 characters', 'error');
            return;
        }
        
        try {
            this.showLoading(true);
            
            if (this.editingNetwork) {
                // Update existing network
                data.id = this.editingNetwork.id;
                await this.makeRequest('/api/whitelist/update', {
                    method: 'PUT',
                    body: JSON.stringify(data)
                });
                this.showMessage('Network updated successfully', 'success');
            } else {
                // Add new network
                await this.makeRequest('/api/whitelist/add', {
                    method: 'POST',
                    body: JSON.stringify(data)
                });
                this.showMessage('Network added successfully', 'success');
            }
            
            this.hideModal();
            this.loadNetworks();
            this.loadStats();
            
        } catch (error) {
            this.showMessage(`Failed to save network: ${error.message}`, 'error');
        } finally {
            this.showLoading(false);
        }
    }
    
    async toggleNetwork(id, enabled) {
        try {
            await this.makeRequest('/api/whitelist/toggle', {
                method: 'PUT',
                body: JSON.stringify({ id, enabled })
            });
            
            this.showMessage(`Network ${enabled ? 'enabled' : 'disabled'}`, 'success');
            this.loadNetworks();
            this.loadStats();
            
        } catch (error) {
            this.showMessage(`Failed to toggle network: ${error.message}`, 'error');
        }
    }
    
    async deleteNetwork(id) {
        if (!confirm('Are you sure you want to delete this network from the whitelist?')) {
            return;
        }
        
        try {
            this.showLoading(true);
            
            await this.makeRequest('/api/whitelist/delete', {
                method: 'DELETE',
                body: JSON.stringify({ id })
            });
            
            this.showMessage('Network deleted successfully', 'success');
            this.loadNetworks();
            this.loadStats();
            
        } catch (error) {
            this.showMessage(`Failed to delete network: ${error.message}`, 'error');
        } finally {
            this.showLoading(false);
        }
    }
    
    showImportModal() {
        $('#import-file').val('');
        $('#import-data').val('');
        $('#backup-before-import').prop('checked', true);
        $('#import-modal').show();
    }
    
    async handleImport() {
        const fileInput = document.getElementById('import-file');
        const textInput = document.getElementById('import-data');
        const createBackup = document.getElementById('backup-before-import').checked;
        
        let data;
        
        try {
            if (fileInput.files.length > 0) {
                const fileContent = await this.readFile(fileInput.files[0]);
                data = JSON.parse(fileContent);
            } else if (textInput.value.trim()) {
                data = JSON.parse(textInput.value.trim());
            } else {
                this.showMessage('Please select a file or paste JSON data', 'error');
                return;
            }
            
            this.showLoading(true);
            
            await this.makeRequest('/api/whitelist/import', {
                method: 'POST',
                body: JSON.stringify({ data, create_backup: createBackup })
            });
            
            this.showMessage('Whitelist imported successfully', 'success');
            this.hideImportModal();
            this.loadNetworks();
            this.loadStats();
            
        } catch (error) {
            this.showMessage(`Import failed: ${error.message}`, 'error');
        } finally {
            this.showLoading(false);
        }
    }
    
    async exportWhitelist() {
        try {
            const data = await this.makeRequest('/api/whitelist/export');
            
            const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
            const url = URL.createObjectURL(blob);
            
            const a = document.createElement('a');
            a.href = url;
            a.download = `pwnagotchi_whitelist_${new Date().toISOString().slice(0, 10)}.json`;
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            
            URL.revokeObjectURL(url);
            this.showMessage('Whitelist exported successfully', 'success');
            
        } catch (error) {
            this.showMessage(`Export failed: ${error.message}`, 'error');
        }
    }
    
    handleFileUpload(e) {
        const file = e.target.files[0];
        if (!file) return;
        
        if (file.type !== 'application/json' && !file.name.endsWith('.json')) {
            this.showMessage('Please select a JSON file', 'error');
            e.target.value = '';
            return;
        }
        
        if (file.size > 10 * 1024 * 1024) { // 10MB limit
            this.showMessage('File is too large (max 10MB)', 'error');
            e.target.value = '';
            return;
        }
    }
    
    readFile(file) {
        return new Promise((resolve, reject) => {
            const reader = new FileReader();
            reader.onload = e => resolve(e.target.result);
            reader.onerror = e => reject(new Error('Failed to read file'));
            reader.readAsText(file);
        });
    }
    
    toggleRegexPattern(show) {
        const group = $('#regex-pattern-group');
        if (show) {
            group.show();
            $('#network-regex-pattern').prop('required', true);
        } else {
            group.hide();
            $('#network-regex-pattern').prop('required', false).val('');
        }
    }
    
    hideModal() {
        $('#network-modal').hide();
        this.editingNetwork = null;
    }
    
    hideImportModal() {
        $('#import-modal').hide();
    }
    
    showLoading(show) {
        const overlay = $('#loading-overlay');
        if (show) {
            overlay.show();
        } else {
            overlay.hide();
        }
    }
    
    showMessage(text, type = 'info') {
        const container = $('#messages');
        const id = 'msg-' + Date.now();
        
        const message = $(`
            <div id="${id}" class="message message-${type}">
                <span class="message-text">${this.escapeHtml(text)}</span>
                <button class="message-close" onclick="$('#${id}').remove()">&times;</button>
            </div>
        `);
        
        container.append(message);
        
        // Auto-remove after 5 seconds
        setTimeout(() => {
            message.fadeOut(() => message.remove());
        }, 5000);
    }
    
    validateBSSID(bssid) {
        const pattern = /^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$/;
        return pattern.test(bssid);
    }
    
    escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }
}

// Initialize when document is ready
$(document).ready(() => {
    window.whitelistManager = new WhitelistManager();
});

// Utility functions for global access
window.WhitelistUtils = {
    formatDate: (dateString) => {
        if (!dateString) return 'N/A';
        return new Date(dateString).toLocaleString();
    },
    
    formatTags: (tags) => {
        if (!Array.isArray(tags) || tags.length === 0) return '';
        return tags.map(tag => `<span class="tag">${tag}</span>`).join(' ');
    },
    
    validateSSID: (ssid) => {
        return ssid && ssid.length <= 32 && ssid.length > 0;
    },
    
    validateBSSID: (bssid) => {
        const pattern = /^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$/;
        return pattern.test(bssid);
    }
};