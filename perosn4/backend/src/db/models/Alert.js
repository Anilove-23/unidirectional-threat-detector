// In-Memory storage repository with helper methods for querying & filtering
const memoryStore = new Map();

class AlertModel {
  /**
   * Save a single alert object
   * @param {Object} alertData 
   * @returns {Object} saved alert with generated id/meta if needed
   */
  static async saveAlert(alertData) {
    const alertId = alertData.flow_id;
    const record = {
      _id: alertId,
      ...alertData,
      createdAt: alertData.timestamp ? new Date(alertData.timestamp) : new Date()
    };
    
    memoryStore.set(alertId, record);
    return record;
  }

  /**
   * Fetch paginated list of alerts, sorted newest first
   * @param {Object} options { page, limit }
   */
  static async getAlerts({ page = 1, limit = 20 } = {}) {
    const all = Array.from(memoryStore.values()).sort(
      (a, b) => new Date(b.timestamp || b.createdAt) - new Date(a.timestamp || a.createdAt)
    );

    const startIndex = (page - 1) * limit;
    const paginated = all.slice(startIndex, startIndex + limit);

    return {
      total: all.length,
      page,
      limit,
      totalPages: Math.ceil(all.length / limit) || 1,
      alerts: paginated
    };
  }

  /**
   * Find an alert by flow_id
   * @param {String} flowId 
   */
  static async getAlertByFlowId(flowId) {
    return memoryStore.get(flowId) || null;
  }

  /**
   * Filtered search for historical alerts
   * @param {Object} filters { threat_class, severity, from, to, page, limit }
   */
  static async searchAlerts({ threat_class, severity, from, to, page = 1, limit = 20 }) {
    let results = Array.from(memoryStore.values());

    if (threat_class) {
      const tc = threat_class.toLowerCase();
      results = results.filter(a => a.threat_class && a.threat_class.toLowerCase() === tc);
    }

    if (severity) {
      const sev = severity.toUpperCase();
      results = results.filter(a => a.severity && a.severity.toUpperCase() === sev);
    }

    if (from) {
      const fromDate = new Date(from);
      if (!isNaN(fromDate.getTime())) {
        results = results.filter(a => new Date(a.timestamp || a.createdAt) >= fromDate);
      }
    }

    if (to) {
      const toDate = new Date(to);
      if (!isNaN(toDate.getTime())) {
        results = results.filter(a => new Date(a.timestamp || a.createdAt) <= toDate);
      }
    }

    // Sort newest first
    results.sort((a, b) => new Date(b.timestamp || b.createdAt) - new Date(a.timestamp || a.createdAt));

    const startIndex = (page - 1) * limit;
    const paginated = results.slice(startIndex, startIndex + limit);

    return {
      total: results.length,
      page: Number(page),
      limit: Number(limit),
      totalPages: Math.ceil(results.length / limit) || 1,
      alerts: paginated
    };
  }

  /**
   * Get total count of stored alerts
   */
  static async getCount() {
    return memoryStore.size;
  }

  /**
   * Clear memory store (used in testing)
   */
  static async clearAll() {
    memoryStore.clear();
  }
}

module.exports = AlertModel;
