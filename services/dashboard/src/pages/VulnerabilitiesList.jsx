import { useState, useEffect } from 'react';
import api from '../api/client';
import SeverityBadge from '../components/SeverityBadge';

export default function VulnerabilitiesList() {
  const [vulnerabilities, setVulnerabilities] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const fetchVulns = async () => {
      try {
        const res = await api.get('/vulnerabilities');
        setVulnerabilities(res.data.items || []);
      } catch (err) {
        console.error(err);
      } finally {
        setLoading(false);
      }
    };
    fetchVulns();
  }, []);

  return (
    <div className="p-8">
      <h1 className="text-3xl font-bold text-gray-900 mb-2">Todas as Vulnerabilidades</h1>
      <p className="text-slate-500 mb-8">Gestão centralizada de falhas encontradas em todos os scans do DevSecOps.</p>
      
      {loading ? (
        <div className="text-center py-12 text-slate-500">Carregando dados de vulnerabilidades...</div>
      ) : (
        <div className="bg-white shadow-sm rounded-xl border border-gray-100 overflow-hidden">
          <table className="min-w-full divide-y divide-gray-200">
            <thead className="bg-slate-50">
              <tr>
                <th className="px-6 py-4 text-left text-xs font-bold text-slate-500 uppercase tracking-wider">Severidade</th>
                <th className="px-6 py-4 text-left text-xs font-bold text-slate-500 uppercase tracking-wider">Identificador da Regra</th>
                <th className="px-6 py-4 text-left text-xs font-bold text-slate-500 uppercase tracking-wider">Localização (Arquivo:Linha)</th>
                <th className="px-6 py-4 text-left text-xs font-bold text-slate-500 uppercase tracking-wider">Detalhes e IA Helper</th>
              </tr>
            </thead>
            <tbody className="bg-white divide-y divide-gray-100">
              {vulnerabilities.map(v => (
                <tr key={v.id} className="hover:bg-slate-50 transition-colors">
                  <td className="px-6 py-5 whitespace-nowrap">
                    <SeverityBadge severity={v.severity} />
                  </td>
                  <td className="px-6 py-5 whitespace-nowrap text-sm font-bold text-slate-700">
                    {v.rule_id}
                  </td>
                  <td className="px-6 py-5 whitespace-nowrap text-sm text-slate-500 font-mono">
                    {v.file_path}:{v.line_number}
                  </td>
                  <td className="px-6 py-5 text-sm text-slate-600">
                    <div className="font-semibold text-slate-800">{v.title}</div>
                    <div className="text-xs text-slate-500 mt-1">{v.description}</div>
                    {v.ai_suggestion && (
                      <div className="mt-2 p-2 bg-indigo-50 border border-indigo-100 rounded text-xs text-indigo-800 font-mono">
                        ✨ Sugestão IA: {v.ai_suggestion.substring(0, 80)}...
                      </div>
                    )}
                  </td>
                </tr>
              ))}
              {vulnerabilities.length === 0 && (
                <tr>
                  <td colSpan="4" className="px-6 py-12 text-center text-slate-500">
                    Nenhuma vulnerabilidade registrada. Bom trabalho!
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
