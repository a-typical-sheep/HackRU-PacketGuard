// app.js

const { useState, useEffect, useRef } = React;
const fs = require('fs');
const path = require('path');

function App() {
  const [darkMode, setDarkMode] = useState(false);
  const [ipAddress, setIpAddress] = useState('');
  const [benignPackets, setBenignPackets] = useState([]);
  const [maliciousPackets, setMaliciousPackets] = useState([]);
  const [allPackets, setAllPackets] = useState([]);
  const [stats, setStats] = useState({
    totalPackets: 0,
    packetTypes: 0,
    timeTaken: '0h 0m',
    threatsDetected: 0,
  });
  const [suggestedIp, setSuggestedIp] = useState(null);

  const allPacketsChartRef = useRef(null);
  const benignPacketsChartRef = useRef(null);
  const maliciousPacketsChartRef = useRef(null);

  const allPacketsChartInstance = useRef(null);
  const benignPacketsChartInstance = useRef(null);
  const maliciousPacketsChartInstance = useRef(null);

  useEffect(() => {
    if (darkMode) {
      document.body.classList.add('dark-mode');
    } else {
      document.body.classList.remove('dark-mode');
    }
  }, [darkMode]);

  function parseBenignPacketLine(line) {
    const parts = line.split(' - ');
    if (parts.length < 2) return null;

    const timestampStr = parts[0].trim();
    const timestamp = new Date(timestampStr);
    if (isNaN(timestamp)) {
      console.error('Invalid timestamp in benign packet:', timestampStr);
      return null;
    }

    const jsonStart = parts[1].indexOf('{');
    if (jsonStart === -1) return null;

    const jsonString = parts[1].slice(jsonStart).replace(/'/g, '"');
    try {
      const packet = JSON.parse(jsonString);
      packet.timestamp = timestamp;
      packet.type = 'benign';
      return packet;
    } catch (error) {
      console.error('Error parsing benign packet JSON:', error);
      return null;
    }
  }

  function parseMaliciousPacketLine(line) {
    const parts = line.split(' - ');
    if (parts.length < 2) return null;

    const timestampStr = parts[0].trim();
    const timestamp = new Date(timestampStr);
    if (isNaN(timestamp)) {
      console.error('Invalid timestamp in malicious packet:', timestampStr);
      return null;
    }

    const jsonStart = parts[1].indexOf('{');
    if (jsonStart === -1) return null;

    const jsonString = parts[1].slice(jsonStart).replace(/'/g, '"');
    try {
      const packet = JSON.parse(jsonString);
      packet.timestamp = timestamp;
      packet.type = 'malicious';
      return packet;
    } catch (error) {
      console.error('Error parsing malicious packet JSON:', error);
      return null;
    }
  }

  useEffect(() => {
    let isMounted = true;

    const benignLogPath = path.join(__dirname, 'benign_packets.log');
    const maliciousLogPath = path.join(__dirname, 'malicious_packets.log');

    const readBenignLog = () => {
      fs.readFile(benignLogPath, 'utf8', (err, data) => {
        if (err) {
          console.error('Error reading benign log file:', err);
          return;
        }
        if (isMounted) {
          const packets = data
            .trim()
            .split('\n')
            .map(parseBenignPacketLine)
            .filter((p) => p);
          setBenignPackets(packets);
          console.log('Benign Packets Updated:', packets);
        }
      });
    };

    const readMaliciousLog = () => {
      fs.readFile(maliciousLogPath, 'utf8', (err, data) => {
        if (err) {
          console.error('Error reading malicious log file:', err);
          return;
        }
        if (isMounted) {
          const packets = data
            .trim()
            .split('\n')
            .map(parseMaliciousPacketLine)
            .filter((p) => p);
          setMaliciousPackets(packets);
          console.log('Malicious Packets Updated:', packets);
        }
      });
    };

    // Watch Benign Log File
    fs.watchFile(benignLogPath, { interval: 1000 }, (curr, prev) => {
      if (curr.mtime !== prev.mtime && isMounted) {
        readBenignLog();
      }
    });

    fs.watchFile(maliciousLogPath, { interval: 1000 }, (curr, prev) => {
      if (curr.mtime !== prev.mtime && isMounted) {
        readMaliciousLog();
      }
    });

    readBenignLog();
    readMaliciousLog();

    return () => {
      isMounted = false;
      fs.unwatchFile(benignLogPath);
      fs.unwatchFile(maliciousLogPath);
    };
  }, []);

  useEffect(() => {
    const combinedPackets = [...benignPackets, ...maliciousPackets];
    setAllPackets(combinedPackets);

    const totalPackets = combinedPackets.length;
    const packetTypesSet = new Set(combinedPackets.map((p) => p.Protocol));
    const threatsDetected = maliciousPackets.length;

    let timeTaken = '0h 0m';
    if (combinedPackets.length > 1) {
      const times = combinedPackets.map((p) => new Date(p.timestamp).getTime());
      const maxTime = Math.max(...times);
      const minTime = Math.min(...times);
      const duration = maxTime - minTime;
      const hours = Math.floor(duration / 3600000);
      const minutes = Math.floor((duration % 3600000) / 60000);
      timeTaken = `${hours}h ${minutes}m`;
    }

    setStats({
      totalPackets,
      packetTypes: packetTypesSet.size,
      timeTaken,
      threatsDetected,
    });

    const ipCounts = {};
    maliciousPackets.forEach((packet) => {
      const ip = packet['Source IP'];
      ipCounts[ip] = (ipCounts[ip] || 0) + 1;
    });

    const ipKeys = Object.keys(ipCounts);
    let maxIp = null;
    if (ipKeys.length > 0) {
      maxIp = ipKeys.reduce((a, b) => (ipCounts[a] > ipCounts[b] ? a : b));
    }

    setSuggestedIp(maxIp);
    console.log('Statistics Updated:', { totalPackets, packetTypes: packetTypesSet.size, timeTaken, threatsDetected, suggestedIp: maxIp });
  }, [benignPackets, maliciousPackets]);

  useEffect(() => {
    function getPacketCounts(packets) {
      const countsMap = new Map();
      packets.forEach((packet) => {
        const time = new Date(packet.timestamp);
        time.setSeconds(0, 0);
        const timeKey = time.getTime();
        countsMap.set(timeKey, (countsMap.get(timeKey) || 0) + 1);
      });
      const sortedEntries = Array.from(countsMap.entries()).sort(
        (a, b) => a[0] - b[0]
      );
      const labels = sortedEntries.map((entry) =>
        new Date(entry[0]).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
      );
      const data = sortedEntries.map((entry) => entry[1]);
      return { labels, data };
    }

    if (!allPacketsChartInstance.current && allPacketsChartRef.current) {
      allPacketsChartInstance.current = new Chart(allPacketsChartRef.current, {
        type: 'line',
        data: {
          labels: [],
          datasets: [
            {
              label: 'All Packets',
              data: [],
              borderColor: '#007bff',
              backgroundColor: '#007bff',
              fill: false,
              tension: 0.1,
            },
          ],
        },
        options: {
          responsive: true,
          plugins: {
            legend: {
              position: 'top',
            },
          },
          scales: {
            x: {
              type: 'category',
              title: { display: true, text: 'Time' },
            },
            y: {
              title: { display: true, text: 'Number of Packets' },
              beginAtZero: true,
              ticks: {
                precision:0
              }
            },
          },
        },
      });
    }

    if (!benignPacketsChartInstance.current && benignPacketsChartRef.current) {
      benignPacketsChartInstance.current = new Chart(benignPacketsChartRef.current, {
        type: 'line',
        data: {
          labels: [],
          datasets: [
            {
              label: 'Benign Packets',
              data: [],
              borderColor: '#28a745',
              backgroundColor: '#28a745',
              fill: false,
              tension: 0.1,
            },
          ],
        },
        options: {
          responsive: true,
          plugins: {
            legend: {
              position: 'top',
            },
          },
          scales: {
            x: {
              type: 'category',
              title: { display: true, text: 'Time' },
            },
            y: {
              title: { display: true, text: 'Number of Packets' },
              beginAtZero: true,
              ticks: {
                precision:0
              }
            },
          },
        },
      });
    }

    if (!maliciousPacketsChartInstance.current && maliciousPacketsChartRef.current) {
      maliciousPacketsChartInstance.current = new Chart(maliciousPacketsChartRef.current, {
        type: 'line',
        data: {
          labels: [],
          datasets: [
            {
              label: 'Malicious Packets',
              data: [],
              borderColor: '#dc3545',
              backgroundColor: '#dc3545',
              fill: false,
              tension: 0.1,
            },
          ],
        },
        options: {
          responsive: true,
          plugins: {
            legend: {
              position: 'top',
            },
          },
          scales: {
            x: {
              type: 'category',
              title: { display: true, text: 'Time' },
            },
            y: {
              title: { display: true, text: 'Number of Packets' },
              beginAtZero: true,
              ticks: {
                precision:0
              }
            },
          },
        },
      });
    }

    return () => {
      if (allPacketsChartInstance.current) {
        allPacketsChartInstance.current.destroy();
        allPacketsChartInstance.current = null;
      }
      if (benignPacketsChartInstance.current) {
        benignPacketsChartInstance.current.destroy();
        benignPacketsChartInstance.current = null;
      }
      if (maliciousPacketsChartInstance.current) {
        maliciousPacketsChartInstance.current.destroy();
        maliciousPacketsChartInstance.current = null;
      }
    };
  }, []);

  // update chart
  useEffect(() => {
    function getPacketCounts(packets) {
      const countsMap = new Map();
      packets.forEach((packet) => {
        const time = new Date(packet.timestamp);
        time.setSeconds(0, 0);
        const timeKey = time.getTime();
        countsMap.set(timeKey, (countsMap.get(timeKey) || 0) + 1);
      });
      const sortedEntries = Array.from(countsMap.entries()).sort(
        (a, b) => a[0] - b[0]
      );
      const labels = sortedEntries.map((entry) =>
        new Date(entry[0]).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
      );
      const data = sortedEntries.map((entry) => entry[1]);
      return { labels, data };
    }

    if (allPacketsChartInstance.current) {
      const packetCounts = getPacketCounts(allPackets);
      allPacketsChartInstance.current.data.labels = packetCounts.labels;
      allPacketsChartInstance.current.data.datasets[0].data = packetCounts.data;
      allPacketsChartInstance.current.update();
      console.log('All Packets Chart Updated:', packetCounts);
    }

    if (benignPacketsChartInstance.current) {
      const packetCounts = getPacketCounts(benignPackets);
      benignPacketsChartInstance.current.data.labels = packetCounts.labels;
      benignPacketsChartInstance.current.data.datasets[0].data = packetCounts.data;
      benignPacketsChartInstance.current.update();
      console.log('Benign Packets Chart Updated:', packetCounts);
    }

    if (maliciousPacketsChartInstance.current) {
      const packetCounts = getPacketCounts(maliciousPackets);
      maliciousPacketsChartInstance.current.data.labels = packetCounts.labels;
      maliciousPacketsChartInstance.current.data.datasets[0].data = packetCounts.data;
      maliciousPacketsChartInstance.current.update();
      console.log('Malicious Packets Chart Updated:', packetCounts);
    }
  }, [allPackets, benignPackets, maliciousPackets]);

  return (
    <div style={{ padding: '24px 32px' }}>
      {/* toggle */}
      <div
        style={{
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
          marginBottom: '32px',
        }}
      >
        <h1 style={{ fontSize: '28px', fontWeight: '600' }}>Welcome, User</h1>

        <div
          style={{
            display: 'flex',
            alignItems: 'center',
            gap: '8px',
          }}
        >
          <span>☀️</span>
          <button
            onClick={() => setDarkMode(!darkMode)}
            style={{
              width: '40px',
              height: '24px',
              borderRadius: '12px',
              background: darkMode ? '#000' : '#e2e2e2',
              position: 'relative',
              border: 'none',
              cursor: 'pointer',
            }}
          >
            <div
              style={{
                width: '20px',
                height: '20px',
                borderRadius: '50%',
                background: '#fff',
                position: 'absolute',
                top: '2px',
                left: darkMode ? '18px' : '2px',
                transition: 'left 0.2s',
              }}
            />
          </button>
          <span>🌙</span>
        </div>
      </div>

      {/* graphs */}
      <div
        style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(3, 1fr)',
          gap: '24px',
          marginBottom: '24px',
        }}
      >
        <div className="card">
          <h2 style={{ fontSize: '20px', marginBottom: '16px' }}>
            All Packet Data
          </h2>
          <canvas ref={allPacketsChartRef}></canvas>
        </div>

        <div className="card">
          <h2 style={{ fontSize: '20px', marginBottom: '16px' }}>
            Benign Packet Data
          </h2>
          <canvas ref={benignPacketsChartRef}></canvas>
        </div>

        <div className="card">
          <h2 style={{ fontSize: '20px', marginBottom: '16px' }}>
            Malicious Packet Data
          </h2>
          <canvas ref={maliciousPacketsChartRef}></canvas>
        </div>
      </div>

      {/* warning */}
      <div className="warning-banner">
        <span className="warning-icon">⚠️</span>
        <span style={{ color: '#666' }}>
          {suggestedIp
            ? `Suggestion: Consider blocking ${suggestedIp} IP address.`
            : 'No suggestions at this time.'}
        </span>
      </div>

      {/* buttons */}
      <div
        style={{
          display: 'flex',
          gap: '12px',
          marginBottom: '24px',
        }}
      >
        <div style={{ flex: 1 }}>
          <p
            style={{
              fontSize: '14px',
              color: '#666',
              marginBottom: '8px',
            }}
          >
            Manually add IP to blacklist:
          </p>
          <input
            type="text"
            placeholder="Enter IP address"
            value={ipAddress}
            onChange={(e) => setIpAddress(e.target.value)}
            style={{ width: '100%' }}
          />
        </div>
        <button className="btn-primary" style={{ marginTop: '24px' }}>
          Add
        </button>
        <button className="btn-primary" style={{ marginTop: '24px' }}>
          <span style={{ marginRight: '8px' }}>↻</span>
          Update Model
        </button>
        <button className="btn-danger" style={{ marginTop: '24px' }}>
          <span style={{ marginRight: '8px' }}>🛡️</span>
          Block All Malicious IPs
        </button>
      </div>

      {/* stats */}
      <div className="stats-card">
        <h2
          style={{
            fontSize: '20px',
            marginBottom: '24px',
          }}
        >
          Summary Statistics
        </h2>

        <div
          style={{
            display: 'grid',
            gridTemplateColumns: 'repeat(4, 1fr)',
            gap: '24px',
          }}
        >
          <div>
            <h3
              style={{
                fontSize: '14px',
                color: '#666',
                marginBottom: '8px',
              }}
            >
              Total Packets Scanned
            </h3>
            <p
              style={{
                fontSize: '24px',
                fontWeight: '600',
              }}
            >
              {stats.totalPackets.toLocaleString()}
            </p>
          </div>

          <div>
            <h3
              style={{
                fontSize: '14px',
                color: '#666',
                marginBottom: '8px',
              }}
            >
              Types of Packets
            </h3>
            <p
              style={{
                fontSize: '24px',
                fontWeight: '600',
              }}
            >
              {stats.packetTypes}
            </p>
          </div>

          <div>
            <h3
              style={{
                fontSize: '14px',
                color: '#666',
                marginBottom: '8px',
              }}
            >
              Time Taken
            </h3>
            <p
              style={{
                fontSize: '24px',
                fontWeight: '600',
              }}
            >
              {stats.timeTaken}
            </p>
          </div>

          <div>
            <h3
              style={{
                fontSize: '14px',
                color: '#666',
                marginBottom: '8px',
              }}
            >
              Threats Detected
            </h3>
            <p
              style={{
                fontSize: '24px',
                fontWeight: '600',
                color: '#ff4757',
              }}
            >
              {stats.threatsDetected}
            </p>
          </div>
        </div>
      </div>
    </div>
  );
}

ReactDOM.render(<App />, document.getElementById('root'));
