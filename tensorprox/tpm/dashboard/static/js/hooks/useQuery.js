// useQuery.js - Data Fetching Hook for TPM Dashboard
const { useState, useEffect, useCallback, useRef, useMemo } = React;

// Simple hash for params to use as cache key
function hashParams(params) {
    return JSON.stringify(params);
}

// Global cache for query results
const queryCache = new Map();

// Cache entry TTL (5 minutes default)
const CACHE_TTL = 5 * 60 * 1000;

/**
 * Get cached data if still valid
 * @param {string} cacheKey - The cache key
 * @returns {object|null} - Cached data or null if expired/missing
 */
function getCachedData(cacheKey) {
    const cached = queryCache.get(cacheKey);
    if (!cached) return null;

    const now = Date.now();
    if (now - cached.timestamp > CACHE_TTL) {
        queryCache.delete(cacheKey);
        return null;
    }

    return cached.data;
}

/**
 * Set data in cache
 * @param {string} cacheKey - The cache key
 * @param {object} data - Data to cache
 */
function setCachedData(cacheKey, data) {
    queryCache.set(cacheKey, {
        data,
        timestamp: Date.now()
    });
}

/**
 * Clear all cached data (useful on logout or manual refresh)
 */
function clearQueryCache() {
    queryCache.clear();
}

/**
 * useQuery - Main data fetching hook
 *
 * @param {string} queryName - Name of the query to execute
 * @param {object} params - Query parameters
 * @param {object} options - Configuration options
 * @param {number} options.refreshInterval - Auto-refresh interval in ms (0 = disabled)
 * @param {boolean} options.enabled - Whether to fetch (default: true)
 * @param {function} options.onSuccess - Callback on successful fetch
 * @param {function} options.onError - Callback on error
 * @param {any} options.initialData - Initial data before first fetch
 * @param {boolean} options.useCache - Whether to use cached data (default: true)
 *
 * @returns {object} Query result with data, loading, error, refetch, etc.
 */
function useQuery(queryName, params = {}, options = {}) {
    const {
        refreshInterval = 0,
        enabled = true,
        onSuccess,
        onError,
        initialData = null,
        useCache = true
    } = options;

    // State
    const [data, setData] = useState(initialData);
    const [count, setCount] = useState(0);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState(null);
    const [lastUpdated, setLastUpdated] = useState(null);

    // Refs for tracking first load vs refresh and cleanup
    const isFirstLoad = useRef(true);
    const intervalRef = useRef(null);
    const abortControllerRef = useRef(null);
    const isMountedRef = useRef(true);

    // Memoize params hash to avoid unnecessary re-fetches
    const paramsHash = useMemo(() => hashParams(params), [params]);
    const cacheKey = useMemo(() => `${queryName}:${paramsHash}`, [queryName, paramsHash]);

    // Stable reference for callbacks
    const onSuccessRef = useRef(onSuccess);
    const onErrorRef = useRef(onError);
    useEffect(() => {
        onSuccessRef.current = onSuccess;
        onErrorRef.current = onError;
    }, [onSuccess, onError]);

    /**
     * Fetch data from the API
     * @param {boolean} isManualRefetch - Whether this is a manual refetch (shows loading)
     */
    const fetchData = useCallback(async (isManualRefetch = false) => {
        if (!enabled) {
            setLoading(false);
            return;
        }

        // Cancel any in-flight request
        if (abortControllerRef.current) {
            abortControllerRef.current.abort();
        }
        abortControllerRef.current = new AbortController();

        // Only show loading spinner on first load or manual refetch
        // Background auto-refreshes should not show loading state
        const shouldShowLoading = isFirstLoad.current || isManualRefetch;
        if (shouldShowLoading) {
            setLoading(true);
        }
        setError(null);

        // Check cache first (only on first load)
        if (isFirstLoad.current && useCache) {
            const cachedData = getCachedData(cacheKey);
            if (cachedData) {
                setData(cachedData.results);
                setCount(cachedData.count);
                setLoading(false);
                isFirstLoad.current = false;
                // Still fetch fresh data in background
            }
        }

        try {
            const response = await fetch('/api/v1/dashboard/query', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ query: queryName, params }),
                signal: abortControllerRef.current.signal
            });

            // Check if component is still mounted
            if (!isMountedRef.current) return;

            if (response.status === 401) {
                // Session expired, trigger re-auth
                window.location.reload();
                return;
            }

            if (!response.ok) {
                let errMessage = 'Query failed';
                try {
                    const errData = await response.json();
                    errMessage = errData.error || errMessage;
                } catch {
                    // Response wasn't JSON
                }
                throw new Error(errMessage);
            }

            const result = await response.json();

            // Check again after await
            if (!isMountedRef.current) return;

            const results = result.results || [];
            const resultCount = result.count ?? results.length;

            setData(results);
            setCount(resultCount);
            setLastUpdated(new Date());
            isFirstLoad.current = false;

            // Cache the result
            if (useCache) {
                setCachedData(cacheKey, { results, count: resultCount });
            }

            // Call success callback
            onSuccessRef.current?.(results);

        } catch (err) {
            // Ignore abort errors
            if (err.name === 'AbortError') return;

            // Check if component is still mounted
            if (!isMountedRef.current) return;

            setError(err.message);
            onErrorRef.current?.(err);
        } finally {
            if (isMountedRef.current) {
                setLoading(false);
            }
        }
    }, [queryName, paramsHash, enabled, cacheKey, useCache]);

    /**
     * Manual refetch function (always shows loading state)
     */
    const refetch = useCallback(() => {
        fetchData(true);
    }, [fetchData]);

    // Initial fetch on mount and when dependencies change
    useEffect(() => {
        isFirstLoad.current = true;
        fetchData(false);

        return () => {
            // Cleanup: abort any pending request
            if (abortControllerRef.current) {
                abortControllerRef.current.abort();
            }
        };
    }, [fetchData]);

    // Auto-refresh interval
    useEffect(() => {
        if (refreshInterval > 0 && enabled) {
            intervalRef.current = setInterval(() => {
                fetchData(false); // Background refresh, no loading state
            }, refreshInterval);

            return () => {
                if (intervalRef.current) {
                    clearInterval(intervalRef.current);
                    intervalRef.current = null;
                }
            };
        }
    }, [fetchData, refreshInterval, enabled]);

    // Cleanup on unmount
    useEffect(() => {
        isMountedRef.current = true;

        return () => {
            isMountedRef.current = false;
            if (intervalRef.current) {
                clearInterval(intervalRef.current);
            }
            if (abortControllerRef.current) {
                abortControllerRef.current.abort();
            }
        };
    }, []);

    return {
        data,
        count,
        loading,
        error,
        refetch,
        lastUpdated,
        // Additional helpers
        isFirstLoad: isFirstLoad.current && loading,
        isEmpty: !loading && !error && (!data || data.length === 0)
    };
}

/**
 * useQueries - Fetch multiple queries in parallel
 *
 * @param {Array} queries - Array of query configurations
 * @param {string} queries[].name - Query name
 * @param {object} queries[].params - Query parameters
 * @param {object} queries[].options - Query options (same as useQuery)
 *
 * @returns {Array} Array of query results in same order as input
 *
 * @example
 * const results = useQueries([
 *   { name: 'last_5_errors', options: { refreshInterval: 15000 } },
 *   { name: 'error_categories_summary', options: { refreshInterval: 60000 } },
 *   { name: 'hubs_by_status', params: { status: 'failed' } }
 * ]);
 *
 * const [errorsResult, categoriesResult, failedHubsResult] = results;
 */
function useQueries(queries) {
    const [results, setResults] = useState(() =>
        queries.map(() => ({
            data: null,
            count: 0,
            loading: true,
            error: null,
            lastUpdated: null,
            isFirstLoad: true,
            isEmpty: false
        }))
    );

    const isMountedRef = useRef(true);
    const abortControllersRef = useRef([]);
    const intervalsRef = useRef([]);
    const isFirstLoadRef = useRef(queries.map(() => true));

    // Serialize queries for dependency tracking
    const queriesKey = useMemo(() =>
        JSON.stringify(queries.map(q => ({
            name: q.name,
            params: q.params || {},
            enabled: q.options?.enabled ?? true
        }))),
        [queries]
    );

    /**
     * Fetch a single query and update its result
     */
    const fetchQuery = useCallback(async (index, query, isManualRefetch = false) => {
        const { name, params = {}, options = {} } = query;
        const { enabled = true, onSuccess, onError, useCache = true } = options;

        if (!enabled) {
            setResults(prev => {
                const updated = [...prev];
                updated[index] = { ...updated[index], loading: false };
                return updated;
            });
            return;
        }

        // Cancel any existing request for this query
        if (abortControllersRef.current[index]) {
            abortControllersRef.current[index].abort();
        }
        abortControllersRef.current[index] = new AbortController();

        const shouldShowLoading = isFirstLoadRef.current[index] || isManualRefetch;

        if (shouldShowLoading) {
            setResults(prev => {
                const updated = [...prev];
                updated[index] = { ...updated[index], loading: true, error: null };
                return updated;
            });
        }

        const cacheKey = `${name}:${hashParams(params)}`;

        // Check cache first
        if (isFirstLoadRef.current[index] && useCache) {
            const cachedData = getCachedData(cacheKey);
            if (cachedData) {
                setResults(prev => {
                    const updated = [...prev];
                    updated[index] = {
                        ...updated[index],
                        data: cachedData.results,
                        count: cachedData.count,
                        loading: false,
                        isFirstLoad: false
                    };
                    return updated;
                });
            }
        }

        try {
            const response = await fetch('/api/v1/dashboard/query', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ query: name, params }),
                signal: abortControllersRef.current[index].signal
            });

            if (!isMountedRef.current) return;

            if (response.status === 401) {
                window.location.reload();
                return;
            }

            if (!response.ok) {
                let errMessage = 'Query failed';
                try {
                    const errData = await response.json();
                    errMessage = errData.error || errMessage;
                } catch {}
                throw new Error(errMessage);
            }

            const result = await response.json();

            if (!isMountedRef.current) return;

            const resultData = result.results || [];
            const resultCount = result.count ?? resultData.length;

            isFirstLoadRef.current[index] = false;

            // Cache the result
            if (useCache) {
                setCachedData(cacheKey, { results: resultData, count: resultCount });
            }

            setResults(prev => {
                const updated = [...prev];
                updated[index] = {
                    data: resultData,
                    count: resultCount,
                    loading: false,
                    error: null,
                    lastUpdated: new Date(),
                    isFirstLoad: false,
                    isEmpty: resultData.length === 0
                };
                return updated;
            });

            onSuccess?.(resultData);

        } catch (err) {
            if (err.name === 'AbortError') return;
            if (!isMountedRef.current) return;

            setResults(prev => {
                const updated = [...prev];
                updated[index] = {
                    ...updated[index],
                    loading: false,
                    error: err.message
                };
                return updated;
            });

            onError?.(err);
        }
    }, []);

    // Initial fetch and setup intervals
    useEffect(() => {
        // Reset state for new queries
        isFirstLoadRef.current = queries.map(() => true);

        // Initial fetch for all queries
        queries.forEach((query, index) => {
            fetchQuery(index, query, false);
        });

        // Setup intervals for auto-refresh
        intervalsRef.current.forEach(clearInterval);
        intervalsRef.current = queries.map((query, index) => {
            const { options = {} } = query;
            const { refreshInterval = 0, enabled = true } = options;

            if (refreshInterval > 0 && enabled) {
                return setInterval(() => {
                    fetchQuery(index, query, false);
                }, refreshInterval);
            }
            return null;
        });

        return () => {
            // Cleanup intervals
            intervalsRef.current.forEach(interval => {
                if (interval) clearInterval(interval);
            });
            // Cleanup abort controllers
            abortControllersRef.current.forEach(controller => {
                if (controller) controller.abort();
            });
        };
    }, [queriesKey, fetchQuery]);

    // Cleanup on unmount
    useEffect(() => {
        isMountedRef.current = true;

        return () => {
            isMountedRef.current = false;
        };
    }, []);

    // Return results with refetch functions attached
    return useMemo(() =>
        results.map((result, index) => ({
            ...result,
            refetch: () => fetchQuery(index, queries[index], true)
        })),
        [results, fetchQuery, queries]
    );
}

/**
 * Recommended refresh intervals based on data type
 * From FRONTEND_SPEC.md
 */
const REFRESH_INTERVALS = {
    // Real-time monitoring (10-30 seconds)
    REALTIME: 15000,
    REALTIME_FAST: 10000,
    REALTIME_SLOW: 30000,

    // Near real-time (60 seconds)
    NEAR_REALTIME: 60000,

    // Moderate (30-60 seconds)
    MODERATE: 45000,
    MODERATE_FAST: 30000,
    MODERATE_SLOW: 60000,

    // Slow (5 minutes)
    SLOW: 300000,

    // Mapping for specific query types
    last_5_errors: 15000,
    error_categories_summary: 60000,
    error_codes_by_category: 60000,
    errors_by_category_last_7_days: 60000,
    errors_over_time_daily: 300000,
    errors_over_time_by_source: 300000,

    miner_overview: 60000,
    top_3_regions: 60000,
    top_10_shards: 60000,
    active_miners_detailed: 60000,
    active_shards_with_origins: 60000,
    active_regions_with_origins: 60000,
    origins_per_shard: 60000,

    origin_trace: 45000,
    origin_trace_detailed: 45000,
    egress_summary: 45000,
    egress_status_by_origin: 45000,

    origin_lifetime_stats: 300000,
    origin_lifetime_distribution: 300000,
    origin_count_over_time: 300000,
    shard_count_over_time: 300000,

    exit_hubs_summary: 60000,
    active_miners: 60000,
    recent_deployments: 30000,
    hubs_by_status: 45000
};

/**
 * Get recommended refresh interval for a query
 * @param {string} queryName - Name of the query
 * @returns {number} Refresh interval in milliseconds
 */
function getRefreshInterval(queryName) {
    return REFRESH_INTERVALS[queryName] || REFRESH_INTERVALS.MODERATE;
}

// Export for use in other modules
// Note: In a non-module environment, these are globally available
if (typeof window !== 'undefined') {
    window.useQuery = useQuery;
    window.useQueries = useQueries;
    window.clearQueryCache = clearQueryCache;
    window.getRefreshInterval = getRefreshInterval;
    window.REFRESH_INTERVALS = REFRESH_INTERVALS;
}
