#!/usr/bin/env python3
"""
Graph Visualization Module
Creates visual representation of IAM privilege graph

Author: Nathaniel Dadson
Independent Security Research
"""

import pickle
import networkx as nx
import matplotlib.pyplot as plt
from typing import Dict, List


class GraphVisualizer:
    """Visualize the IAM privilege graph"""
    
    def __init__(self, graph_file: str = "iam_graph.gpickle"):
        with open(graph_file, 'rb') as f:
            self.graph = pickle.load(f)
        print(f"📂 Loaded graph with {self.graph.number_of_nodes()} nodes and {self.graph.number_of_edges()} edges")
    
    def draw_graph(self, output_file: str = "iam_graph.png"):
        """Draw the graph using matplotlib"""
        plt.figure(figsize=(16, 12))
        
        # Create layout
        pos = nx.spring_layout(self.graph, k=2, iterations=50)
        
        # Color nodes by type
        node_colors = []
        for node in self.graph.nodes():
            node_type = self.graph.nodes[node].get('type', 'unknown')
            if node_type == 'user':
                node_colors.append('lightblue')
            elif node_type == 'role':
                node_colors.append('lightgreen')
            else:
                node_colors.append('gray')
        
        # Draw nodes
        nx.draw_networkx_nodes(self.graph, pos, node_color=node_colors, 
                               node_size=3000, alpha=0.9)
        
        # Draw edges with different colors by risk
        for edge in self.graph.edges(data=True):
            risk = edge[2].get('risk', 'LOW')
            if risk == 'HIGH':
                color = 'red'
                width = 2
            elif risk == 'MEDIUM':
                color = 'orange'
                width = 1.5
            else:
                color = 'gray'
                width = 1
            nx.draw_networkx_edges(self.graph, pos, [(edge[0], edge[1])],
                                   edge_color=color, width=width, alpha=0.7)
        
        # Draw labels
        nx.draw_networkx_labels(self.graph, pos, font_size=10, font_weight='bold')
        
        # Add legend
        from matplotlib.patches import Patch
        legend_elements = [
            Patch(facecolor='lightblue', label='IAM User'),
            Patch(facecolor='lightgreen', label='IAM Role'),
            Patch(facecolor='red', label='High Risk Edge'),
            Patch(facecolor='orange', label='Medium Risk Edge'),
        ]
        plt.legend(handles=legend_elements, loc='upper left')
        
        plt.title("IAM Privilege Graph - Attack Path Visualization", fontsize=16)
        plt.axis('off')
        plt.tight_layout()
        plt.savefig(output_file, dpi=150, bbox_inches='tight')
        print(f"📊 Graph saved to {output_file}")
        plt.show()
    
    def find_attack_paths(self, source: str = None, target: str = None):
        """Find and highlight attack paths"""
        if source and target:
            try:
                path = nx.shortest_path(self.graph, source=source, target=target)
                print(f"\n🔴 Attack Path from {source} to {target}:")
                print(f"   {' → '.join(path)}")
                return path
            except nx.NetworkXNoPath:
                print(f"\n✅ No path found from {source} to {target}")
        else:
            print("\n🔍 Use: find_attack_paths(source='username', target='target_role')")


if __name__ == "__main__":
    viz = GraphVisualizer()
    viz.draw_graph()
