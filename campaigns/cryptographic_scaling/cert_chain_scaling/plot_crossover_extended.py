"""Publication plots for the exact static model; no performance measurements run."""
import math
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt


def plots(output,crossings,sizes):
    plt.rcParams.update({'font.size':9,'pdf.fonttype':42,'ps.fonttype':42,'axes.spines.top':False,'axes.spines.right':False})
    names=list(dict.fromkeys(r['algorithm'] for r in crossings))
    fig,ax=plt.subplots(figsize=(11,5),layout='constrained')
    colors={2:'#747474',3:'#c55013',4:'#247ba0',5:'#6b4c9a'}
    markers={2:'o',3:'D',4:'s',5:'P'}
    for depth in (2,3,4,5):
        rows=[r for r in crossings if r['x509_depth']==depth]
        offset=(depth-3.5)*.13
        for i,r in enumerate(rows):
            crossed=bool(r['crossover_N'])
            y=math.log2(r['crossover_N']) if crossed else 49
            ax.scatter(i+offset,y,color=colors[depth],marker=markers[depth] if crossed else '^',s=65 if depth==3 else 36,
                       facecolors=colors[depth] if crossed else 'none',linewidths=1.5 if depth==3 else 1,zorder=3)
        ax.scatter([],[],color=colors[depth],marker=markers[depth],s=65 if depth==3 else 36,label=f'D={depth}'+(' (representative)' if depth==3 else ''))
    ax.axhline(48,ls=':',color='#666666',lw=1)
    ax.text(.01,49.9,'Open triangles: no crossover through N = 2^48 - 1',transform=ax.get_yaxis_transform(),fontsize=8)
    ax.axhline(10,ls='--',color='#aaaaaa',lw=.8)
    ax.text(.99,10.4,'Native implementation limit: N=1024',ha='right',transform=ax.get_yaxis_transform(),fontsize=8)
    ax.set(xticks=range(len(names)),xticklabels=names,ylabel='log2(first crossover population N)',ylim=(-1,52),title='Landmark MTC versus X.509: exact Certificate-message crossover')
    ax.tick_params(axis='x',rotation=30);ax.grid(axis='y',alpha=.2);ax.legend(loc='upper left',bbox_to_anchor=(0,-.21),ncol=4,frameon=False)
    fig.savefig(output/'crossover-by-depth.pdf');fig.savefig(output/'crossover-by-depth.png',dpi=140);plt.close(fig)
    groups=[['ecdsa-p256','mldsa44','slhdsa128s'],['ecdsa-p384','mldsa65','slhdsa192s'],['ecdsa-p521','mldsa87','slhdsa256s']]
    fig,axes=plt.subplots(3,3,figsize=(12,9),layout='constrained')
    for row,names in enumerate(groups):
        for col,name in enumerate(names):
            ax=axes[row,col];series=[r for r in sizes if r['algorithm']==name]
            x=[math.log2(r['interval_first_N']) for r in series]+[math.log2(series[-1]['interval_last_N'])]
            y=[r['tls_certificate_message_bytes'] for r in series]+[series[-1]['tls_certificate_message_bytes']]
            ax.step(x,y,where='post',color='#146b8c',lw=1.7,label='Exact landmark model')
            anchor=next(r for r in series if r['interval_first_N']<=16<=r['interval_last_N'])
            ax.scatter([4],[anchor['tls_certificate_message_bytes']],s=24,color='#146b8c',zorder=4,label='N=16 fixture')
            for depth in (2,3):
                r=next(r for r in crossings if r['algorithm']==name and r['x509_depth']==depth)
                ax.axhline(r['x509_bytes'],color=colors[depth],ls='--' if depth==2 else '-',lw=1.8 if depth==3 else 1,label=f'X.509 D={depth}')
                if r['crossover_N']:
                    ax.scatter([math.log2(r['crossover_N'])],[r['crossover_mtc_bytes']],color=colors[depth],marker='D',s=25,zorder=4)
            ax.axvline(10,color='#aaaaaa',ls=':',lw=.8)
            ax.set(title=name,xlim=(0,48),yscale='log',xticks=[0,10,20,30,40,48])
            ax.grid(alpha=.15);ax.set_xlabel('log2(N)')
            if col==0:ax.set_ylabel(f'Security level {[1,3,5][row]}\nTLS Certificate bytes (log scale)')
    handles,labels=axes[0,0].get_legend_handles_labels()
    fig.legend(handles,labels,loc='outside lower center',ncol=4,frameon=False)
    fig.suptitle('Representative chains: D=2 and D=3 (root excluded from TLS)\nBeyond N=1024: serialization model only',fontsize=13)
    fig.savefig(output/'crossover-curves.pdf');fig.savefig(output/'crossover-curves.png',dpi=140);plt.close(fig)
