"""
Visualization module for ECHO dashboard
Creates interactive Plotly charts
"""
import plotly.graph_objects as go
from typing import Dict, List
from datetime import datetime
import sys
import os

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from utils.helpers import format_timestamp


def create_timeline_chart(flows: List[Dict]) -> List[Dict]:
    """
    Returns data for the custom HTML forensic timeline
    Format: [{'ip': '...', 'sub': '...', 'color': '...', 'bars': [...], 'markers': [...]}]
    """
    if not flows:
        return []
    
    # Group by IP
    grouped = {}
    for flow in flows:
        ip = flow.get('dst_ip', 'Unknown')
        if ip not in grouped:
            grouped[ip] = []
        grouped[ip].append(flow)
    
    # Calculate time bounds
    all_starts = [f.get('start_time', 0) for f in flows]
    min_time = min(all_starts) if all_starts else 0
    max_time = max([f.get('end_time', 0) for f in flows]) if all_starts else 1
    duration = max_time - min_time if max_time > min_time else 1
    
    timeline_data = []
    colors = ['#00d4ff', '#ffa502', '#2ed573', '#ff4757', '#a29bfe']
    
    for i, (ip, ip_flows) in enumerate(list(grouped.items())[:8]): # Show top 8
        bars = []
        markers = []
        for f in ip_flows:
            start_pct = ((f.get('start_time', min_time) - min_time) / duration) * 100
            width_pct = ((f.get('end_time', f.get('start_time', min_time)) - f.get('start_time', min_time)) / duration) * 100
            bars.append({'l': max(0, start_pct), 'w': max(0.5, width_pct)})
            
            # Add markers for large transfers
            if f.get('total_bytes', 0) > 1000000:
                markers.append({'l': start_pct, 'type': 'shift'})
        
        timeline_data.append({
            'ip': ip,
            'sub': f"{len(ip_flows)} sessions",
            'color': colors[i % len(colors)],
            'bars': bars,
            'markers': markers
        })
    
    return timeline_data


def create_signal_matrix(profiles: Dict[str, Dict]) -> List[Dict]:
    """
    Generates data for the Signal Contribution Matrix
    """
    matrix = []
    for ip, prof in list(profiles.items())[:10]:
        score = prof.get('suspicion_score', 0)
        matrix.append({
            'ip': ip,
            'burst': "HIGH" if prof.get('regularity_score', 0) > 0.8 else "MED",
            'rhythm': "HIGH" if prof.get('total_flows', 0) > 20 else "LOW",
            'fingerprint': "HIGH" if prof.get('total_bytes', 0) > 500000 else "MED",
            'infra': "CRITICAL" if score > 80 else "NORMAL",
            'graph': "HIGH" if score > 60 else "MED"
        })
    return matrix


def create_network_graph(graph_data: Dict) -> Dict:
    """
    Returns vis.js compatible nodes and edges
    """
    if not graph_data or 'nodes' not in graph_data or 'edges' not in graph_data:
        return {"nodes": [], "edges": []}
    
    nodes = graph_data['nodes']
    edges = graph_data['edges']
    suspect_ip = graph_data.get('suspect_ip', 'Unknown')
    
    vis_nodes = []
    for node in nodes:
        color = '#00d4ff'
        size = 20
        if node['type'] == 'suspect':
            color = '#ff4757'
            size = 30
        elif node.get('suspicion_score', 0) > 70:
            color = '#ffa502'
        
        vis_nodes.append({
            'id': node['id'],
            'label': node['id'],
            'color': color,
            'size': size,
            'font': {'color': '#fff'},
            '_type': node.get('type', 'Endpoint'),
            '_sessions': node.get('total_flows', 0),
            '_bytes': f"{node.get('total_bytes', 0) / 1024:.1f} KB",
            '_tags': [node['type']]
        })
    
    vis_edges = []
    for edge in edges:
        vis_edges.append({
            'from': edge['source'],
            'to': edge['target'],
            'color': {'color': '#475569', 'opacity': 0.6}
        })
    
    return {"nodes": vis_nodes, "edges": vis_edges}


def create_endpoint_ranking_chart(profiles: Dict[str, Dict]) -> Dict:
    """
    Create bar chart of endpoints ranked by suspicion score
    """
    if not profiles:
        return _empty_chart("No endpoint profiles available")
    
    # Extract and rank profiles
    ranked = []
    for ip, profile in profiles.items():
        score = profile.get('suspicion_score', 0) if isinstance(profile, dict) else 0
        ranked.append({
            'ip': ip,
            'score': score,
            'flows': profile.get('total_flows', 0) if isinstance(profile, dict) else 0,
            'bytes': profile.get('total_bytes', 0) if isinstance(profile, dict) else 0
        })
    
    ranked.sort(key=lambda x: x['score'], reverse=True)
    top_10 = ranked[:10]
    
    trace = go.Bar(
        x=[item['score'] for item in top_10],
        y=[item['ip'] for item in top_10],
        orientation='h',
        marker=dict(
            color=[item['score'] for item in top_10],
            colorscale='YlOrRd',
            showscale=True,
            colorbar=dict(title="Suspicion Score")
        ),
        text=[f"{item['score']:.1f}" for item in top_10],
        textposition='auto',
        hovertemplate=(
            "<b>%{y}</b><br>"
            "Suspicion Score: %{x:.1f}<br>"
            "<extra></extra>"
        )
    )
    
    layout = go.Layout(
        title="Top 10 Endpoints by Suspicion Score",
        xaxis=dict(title="Suspicion Score", gridcolor='#334155'),
        yaxis=dict(title="Remote IP", gridcolor='#334155'),
        plot_bgcolor='#0f172a',
        paper_bgcolor='#1e293b',
        font=dict(color='#e0e0e0'),
        height=600
    )
    
    return {'data': [trace], 'layout': layout}


def create_burst_correlation_chart(correlations: List[Dict]) -> Dict:
    """
    Create scatter plot of burst correlations
    """
    if not correlations:
        return _empty_chart("No correlations detected")
    
    # Extract correlation data
    remote_ips = []
    time_deltas = []
    scores = []
    hover_text = []
    
    for corr in correlations:
        remote_ips.append(corr.get('remote_ip', 'Unknown'))
        time_deltas.append(corr.get('time_delta', 0))
        scores.append(corr.get('correlation_score', 0))
        hover_text.append(
            f"Remote IP: {corr.get('remote_ip', 'Unknown')}<br>"
            f"Time Delta: {corr.get('time_delta', 0):.3f}s<br>"
            f"Score: {corr.get('correlation_score', 0):.2f}"
        )
    
    trace = go.Scatter(
        x=time_deltas,
        y=scores,
        mode='markers',
        marker=dict(
            size=12,
            color=scores,
            colorscale='Viridis',
            showscale=True,
            colorbar=dict(title="Correlation Score")
        ),
        text=remote_ips,
        hovertext=hover_text,
        hoverinfo='text'
    )
    
    layout = go.Layout(
        title=f"Burst Correlation Analysis ({len(correlations)} correlations)",
        xaxis=dict(title="Time Delta (seconds)", gridcolor='#334155'),
        yaxis=dict(title="Correlation Score", gridcolor='#334155'),
        plot_bgcolor='#0f172a',
        paper_bgcolor='#1e293b',
        font=dict(color='#e0e0e0'),
        height=600
    )
    
    return {'data': [trace], 'layout': layout}


def _empty_chart(message: str) -> Dict:
    """Create empty placeholder chart"""
    trace = go.Scatter(
        x=[0],
        y=[0],
        mode='text',
        text=[message],
        textfont=dict(size=20, color='#94a3b8')
    )
    
    layout = go.Layout(
        xaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
        yaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
        plot_bgcolor='#0f172a',
        paper_bgcolor='#1e293b',
        height=400
    )
    
    return {'data': [trace], 'layout': layout}