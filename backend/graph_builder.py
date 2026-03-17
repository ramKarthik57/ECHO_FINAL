"""
Graph builder module
Builds relationship graph between suspect and remote endpoints
"""
import networkx as nx
from typing import Dict, List, Optional
import sys
import os

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from utils.config import *
from utils.helpers import save_json, load_json


class GraphBuilder:
    """Builds communication relationship graphs using NetworkX"""
    
    def __init__(self):
        self.graph = nx.DiGraph()
        self.suspect_ip = None
    
    def build_graph(self, flows: Dict[str, Dict], profiles: Dict[str, Dict], 
                    suspect_ip: str, correlations: List[Dict] = None) -> nx.DiGraph:
        """
        Build a directed graph of communication relationships
        
        Args:
            flows: Dictionary of flow objects
            profiles: Dictionary of endpoint profiles
            suspect_ip: IP address of suspect device
            correlations: Optional list of burst correlations
        
        Returns:
            NetworkX DiGraph object
        """
        self.suspect_ip = suspect_ip
        self.graph = nx.DiGraph()
        
        # Add suspect node (central node)
        self.graph.add_node(suspect_ip, node_type='suspect', label='Suspect Device')
        
        # Add remote endpoints and edges from flows
        for flow_id, flow in flows.items():
            src = flow['src_ip']
            dst = flow['dst_ip']
            
            # Skip if flow doesn't involve suspect
            if src != suspect_ip and dst != suspect_ip:
                continue
            
            # Identify remote endpoint
            remote_ip = dst if src == suspect_ip else src
            
            # Add remote node if not exists
            if remote_ip not in self.graph:
                profile = profiles.get(remote_ip, {})
                self.graph.add_node(
                    remote_ip,
                    node_type='remote',
                    label=remote_ip,
                    total_flows=profile.get('total_flows', 0),
                    total_bytes=profile.get('total_bytes', 0),
                    suspicion_score=self._calculate_node_suspicion(profile)
                )
            
            # Add edge (or update weight if exists)
            if self.graph.has_edge(suspect_ip, remote_ip):
                self.graph[suspect_ip][remote_ip]['weight'] += flow['total_bytes']
                self.graph[suspect_ip][remote_ip]['flow_count'] += 1
            else:
                self.graph.add_edge(
                    suspect_ip,
                    remote_ip,
                    weight=flow['total_bytes'],
                    flow_count=1,
                    edge_type='communication'
                )
        
        # Add correlation information if available
        if correlations:
            self._add_correlation_edges(correlations)
        
        print(f"[+] Built graph with {self.graph.number_of_nodes()} nodes and {self.graph.number_of_edges()} edges")
        return self.graph
    
    def _calculate_node_suspicion(self, profile: Dict) -> float:
        """Calculate suspicion score for a node"""
        if not profile:
            return 0.0
        
        score = 0.0
        
        # High communication frequency
        freq = profile.get('communication_frequency', 0)
        if freq > 0.01:
            score += min(30, freq * 1000)
        
        # Regular communication patterns
        regularity = profile.get('regularity_score', 0)
        score += regularity * 25
        
        # High data volume
        total_bytes = profile.get('total_bytes', 0)
        if total_bytes > 1000000:
            score += min(25, (total_bytes / 1000000) * 5)
        
        # External IP
        if not profile.get('is_private', True):
            score += 20
        
        return min(100, score)
    
    def _add_correlation_edges(self, correlations: List[Dict]) -> None:
        """Add correlation strength as edge attributes"""
        for corr in correlations:
            remote_ip = corr['remote_ip']
            
            if self.graph.has_edge(self.suspect_ip, remote_ip):
                # Add correlation data to existing edge
                if 'correlations' not in self.graph[self.suspect_ip][remote_ip]:
                    self.graph[self.suspect_ip][remote_ip]['correlations'] = []
                
                self.graph[self.suspect_ip][remote_ip]['correlations'].append({
                    'score': corr['correlation_score'],
                    'time_delta': corr['time_delta']
                })
    
    def get_top_connected_nodes(self, n: int = 10) -> List[Dict]:
        """
        Get top N nodes by connection strength
        
        Returns ranked list of nodes with metrics
        """
        if self.suspect_ip not in self.graph:
            return []
        
        neighbors = list(self.graph.neighbors(self.suspect_ip))
        
        ranked = []
        for node in neighbors:
            edge_data = self.graph[self.suspect_ip][node]
            node_data = self.graph.nodes[node]
            
            ranked.append({
                'remote_ip': node,
                'total_bytes': edge_data['weight'],
                'flow_count': edge_data['flow_count'],
                'suspicion_score': node_data.get('suspicion_score', 0),
                'has_correlations': 'correlations' in edge_data
            })
        
        # Sort by total bytes (descending)
        ranked.sort(key=lambda x: x['total_bytes'], reverse=True)
        
        return ranked[:n]
    
    def export_for_visualization(self) -> Dict:
        """
        Export graph in format suitable for web visualization
        
        Returns dict with nodes and edges arrays
        """
        nodes = []
        edges = []
        
        # Export nodes
        for node_id, node_data in self.graph.nodes(data=True):
            nodes.append({
                'id': node_id,
                'label': node_data.get('label', node_id),
                'type': node_data.get('node_type', 'unknown'),
                'suspicion_score': node_data.get('suspicion_score', 0),
                'total_flows': node_data.get('total_flows', 0),
                'total_bytes': node_data.get('total_bytes', 0)
            })
        
        # Export edges
        for src, dst, edge_data in self.graph.edges(data=True):
            edges.append({
                'source': src,
                'target': dst,
                'weight': edge_data.get('weight', 0),
                'flow_count': edge_data.get('flow_count', 0),
                'type': edge_data.get('edge_type', 'unknown'),
                'has_correlations': 'correlations' in edge_data
            })
        
        return {
            'nodes': nodes,
            'edges': edges,
            'suspect_ip': self.suspect_ip
        }
    
    def calculate_centrality_metrics(self) -> Dict[str, Dict]:
        """
        Calculate network centrality metrics
        
        Returns dict of centrality scores for each node
        """
        metrics = {}
        
        # Degree centrality
        degree_cent = nx.degree_centrality(self.graph)
        
        # Betweenness centrality (if graph is large enough)
        if self.graph.number_of_nodes() > 2:
            betweenness_cent = nx.betweenness_centrality(self.graph)
        else:
            betweenness_cent = {node: 0 for node in self.graph.nodes()}
        
        # Combine metrics
        for node in self.graph.nodes():
            metrics[node] = {
                'degree_centrality': degree_cent.get(node, 0),
                'betweenness_centrality': betweenness_cent.get(node, 0)
            }
        
        return metrics
    
    def save_graph(self, filepath: str = GRAPH_FILE) -> bool:
        """Save graph data to JSON"""
        if not self.graph:
            print("[!] No graph to save")
            return False
        
        try:
            graph_data = self.export_for_visualization()
            save_json(graph_data, filepath)
            print(f"[+] Saved graph to {filepath}")
            return True
        except Exception as e:
            print(f"[!] Error saving graph: {e}")
            return False
    
    def get_statistics(self) -> Dict:
        """Get graph statistics"""
        if not self.graph:
            return {}
        
        return {
            'total_nodes': self.graph.number_of_nodes(),
            'total_edges': self.graph.number_of_edges(),
            'suspect_ip': self.suspect_ip,
            'remote_endpoints': self.graph.number_of_nodes() - 1,
            'is_connected': nx.is_weakly_connected(self.graph),
            'density': nx.density(self.graph)
        }


def main():
    """Demo: Build communication graph"""
    print("=" * 60)
    print("ECHO Graph Builder Module")
    print("=" * 60)
    
    # Load flows and profiles
    flows_data = load_json(FLOWS_FILE)
    profiles_data = load_json(os.path.join(DATA_DIR, "endpoint_profiles.json"))
    
    if not flows_data:
        print("[!] No flows found")
        print(f"[*] Run flow_builder.py first")
        return
    
    # Convert to dict if needed
    if isinstance(flows_data, list):
        flows = {f['flow_id']: f for f in flows_data}
    else:
        flows = flows_data
    
    profiles = profiles_data or {}
    
    # Get suspect IP
    if flows:
        first_flow = list(flows.values())[0]
        suspect_ip = first_flow['src_ip']
        print(f"[*] Using {suspect_ip} as suspect IP")
        
        # Build graph
        builder = GraphBuilder()
        graph = builder.build_graph(flows, profiles, suspect_ip)
        
        if graph:
            builder.save_graph()
            
            # Show statistics
            stats = builder.get_statistics()
            print(f"\n[*] Graph Statistics:")
            print(f"    Total nodes: {stats['total_nodes']}")
            print(f"    Total edges: {stats['total_edges']}")
            print(f"    Remote endpoints: {stats['remote_endpoints']}")
            print(f"    Graph density: {stats['density']:.3f}")
            
            # Show top connections
            top_nodes = builder.get_top_connected_nodes(5)
            print(f"\n[*] Top 5 connections:")
            for i, node in enumerate(top_nodes, 1):
                print(f"    {i}. {node['remote_ip']}")
                print(f"       Bytes: {node['total_bytes']:,}, Flows: {node['flow_count']}")
                print(f"       Suspicion: {node['suspicion_score']:.1f}")
    else:
        print("[!] No flows available")


if __name__ == "__main__":
    main()