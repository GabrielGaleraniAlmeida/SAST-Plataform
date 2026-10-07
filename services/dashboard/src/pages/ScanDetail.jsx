import { useState, useEffect } from 'react';
import { useParams } from 'react-router-dom';
import api from '../api/client';
import SeverityBadge from '../components/SeverityBadge';

export default function ScanDetail() {
  const { id } = useParams();
  const [scan, setScan] = useState(null);
  const [vulnerabilities, setVulnerabilities] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const fetchDetail = async () => {
      try {
        const scanRes = await api.get(`/scans/${id}`);
        setScan(scanRes.data);
        const vulnsRes = await api.get(`/vulnerabilities`, { params: { scan_id: id } });
        setVulnerabilities(vulnsRes.data.items || []);
      } catch (err) {
        console.error(err);
      } finally {
        setLoading(false);
      }
    };
    fetchDetail();
  }, [id]);

  if (loading) return <div className="p-8 text-center text-gray-500">Carregando detalhes do scan...</div>;
  if (!scan) return <div className="p-8 text-center text-red-500">Scan não encontrado.</div>;

  return (
    <div className="p-8">
      <div className="mb-6 flex justify-between items-center">
        <div>
          <h1 className="text-2xl font-bold text-gray-900">Detalhes do Scan</h1>
          <p className="text-gray-500 text-sm mt-1">ID: {scan.id}</p>
          <p className="text-gray-500 text-sm mt-1">Repo: {scan.repository_url} | Branch: {scan.branch}</p>
        </div>
        <div className="text-right">
          <span className={`px-4 py-2 rounded-full text-sm font-bold ${
            scan.status === 'completed' ? 'bg-green-100 text-green-800' :
            scan.status === 'failed' ? 'bg-red-100 text-red-800' :
            'bg-blue-100 text-blue-800'
          }`}>
            {scan.status.toUpperCase()}
          </span>
        </div>
      </div>

      <div className="grid grid-cols-3 gap-6 mb-8">
        <div className="bg-white p-6 rounded-xl shadow-sm border border-gray-100">
          <h3 className="text-sm font-medium text-gray-500 uppercase tracking-wider">Linguagem</h3>
          <p className="text-2xl font-semibold text-gray-800 mt-2">{scan.language || 'N/A'}</p>
        </div>
        <div className="bg-white p-6 rounded-xl shadow-sm border border-gray-100">
          <h3 className="text-sm font-medium text-gray-500 uppercase tracking-wider">Arquivos Analisados</h3>
          <p className="text-2xl font-semibold text-gray-800 mt-2">{scan.total_files || 0}</p>
        </div>
        <div className="bg-white p-6 rounded-xl shadow-sm border border-gray-100">
          <h3 className="text-sm font-medium text-gray-500 uppercase tracking-wider">Total de Falhas</h3>
          <p className="text-2xl font-semibold text-gray-800 mt-2">{scan.total_vulnerabilities || 0}</p>
        </div>
      </div>

      <h2 className="text-xl font-bold mb-4 text-gray-800">Vulnerabilidades Encontradas</h2>
      <div className="bg-white shadow-sm rounded-xl border border-gray-100 overflow-hidden">
        {vulnerabilities.length === 0 ? (
          <div className="p-8 text-center text-gray-500">Nenhuma vulnerabilidade encontrada neste scan! 🎉</div>
        ) : (
          <table className="min-w-full divide-y divide-gray-200">
            <thead className="bg-slate-50">
              <tr>
                <th className="px-6 py-4 text-left text-xs font-bold text-gray-500 uppercase tracking-wider">Severidade</th>
                <th className="px-6 py-4 text-left text-xs font-bold text-gray-500 uppercase tracking-wider">Regra (Rule)</th>
                <th className="px-6 py-4 text-left text-xs font-bold text-gray-500 uppercase tracking-wider">Arquivo e Linha</th>
                <th className="px-6 py-4 text-left text-xs font-bold text-gray-500 uppercase tracking-wider">Descrição</th>
              </tr>
            </thead>
            <tbody className="bg-white divide-y divide-gray-100">
              {vulnerabilities.map(v => (
                <tr key={v.id} className="hover:bg-slate-50 transition-colors">
                  <td className="px-6 py-4 whitespace-nowrap">
                    <SeverityBadge severity={v.severity} />
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap text-sm font-medium text-slate-700">
                    {v.rule_id}
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap text-sm text-slate-500 font-mono">
                    {v.file_path}:{v.line_number}
                  </td>
                  <td className="px-6 py-4 text-sm text-slate-600">
                    <span className="font-semibold">{v.title}</span>
                    <p className="text-xs text-slate-400 mt-1 line-clamp-1">{v.description}</p>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}
